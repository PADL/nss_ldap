/* Copyright (C) 1997-2010 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.

   The nss_ldap library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The nss_ldap library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the nss_ldap library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
 */

static char rcsId[] =
  "$Id$";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif
#ifdef HAVE_GSSLDAP_H
#include <gssldap.h>
#endif
#ifdef HAVE_GSSSASL_H
#include <gsssasl.h>
#endif

/* Try to handle systems with both SASL libraries installed */
#if defined(HAVE_SASL_SASL_H) && defined(HAVE_SASL_AUXPROP_REQUEST)
#include <sasl/sasl.h>
#elif defined(HAVE_SASL_H)
#include <sasl.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "ltf.h"
#include "util.h"
#include "dnsconfig.h"
#include "pagectrl.h"

/* Prefer the threads library over the pthreads facility unless running on AIX */
#if defined(HAVE_THREAD_H) && !defined(_AIX)
#ifdef HAVE_PTHREAD_ATFORK
#undef HAVE_PTHREAD_ATFORK
#endif
#endif

/* how many messages to retrieve results for */
#ifndef LDAP_MSG_ONE
#define LDAP_MSG_ONE            0x00
#endif
#ifndef LDAP_MSG_ALL
#define LDAP_MSG_ALL            0x01
#endif
#ifndef LDAP_MSG_RECEIVED
#define LDAP_MSG_RECEIVED       0x02
#endif

#ifdef HAVE_LDAP_LD_FREE
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
extern int ldap_ld_free (LDAP * ld, int close, LDAPControl **,
			 LDAPControl **);
#else
extern int ldap_ld_free (LDAP * ld, int close);
#endif /* OPENLDAP 2.x */
#endif /* HAVE_LDAP_LD_FREE */

NSS_LDAP_DEFINE_LOCK (__lock);

/*
 * the configuration is read by the first call to do_open().
 * Pointers to elements of the list are passed around but should not
 * be freed.
 */
static char __configbuf[NSS_LDAP_CONFIG_BUFSIZ];

#ifdef HAVE_SIGACTION
static struct sigaction __stored_handler;
static int __sigaction_retval = -1;
#else
static void (*__sigpipe_handler) (int) = SIG_DFL;
#endif /* HAVE_SIGACTION */

/*
 * SASL mechs setup
 */

static ldap_session_mech_setup_t sasl_setups[] = {
  __nss_ldap_krb5_cache
};

/*
 * Global LDAP session.
 */
static ldap_session_t __session =
  {
    NULL,		/* LDAP session connection */
    NULL,		/* LDAP session configuration data */
    0,			/* Timestamp of last activity */
    LS_UNINITIALIZED,	/* LDAP session current state */
    0,			/* Index of URI used for this connection */
    -1,			/* Initial PID information */
    -1,			/* Initial EUID information */
    NULL,		/* Head of Opaque pointer list for extensions */
    NULL		/* SASL mechanism entry points */
    /* There are 2 large data areas at the end of the structure for socket addresses */
  };

/* Track initial operation of the library when threading active */
#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
static pthread_once_t __once = PTHREAD_ONCE_INIT;
#endif

#ifdef LBER_OPT_LOG_PRINT_FILE
static FILE *__debugfile;
#endif /* LBER_OPT_LOG_PRINT_FILE */

#ifdef HAVE_LDAPSSL_CLIENT_INIT
static int __ssl_initialized = 0;
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)

# if defined(HAVE_PTHREAD_ATFORK)
# define ATFORK_DO pthread_atfork
# else
# define ATFORK_DO __libc_atfork
# endif

/*
 * Prepare for fork (); lock mutex.
 */
static void do_atfork_prepare (void);

/*
 * Forked in parent, unlock mutex.
 */
static void do_atfork_parent (void);

/*
 * Forked in child; close LDAP socket, unlock mutex.
 */
static void do_atfork_child (void);

/*
 * Install handlers for atfork, called once.
 */
static void do_atfork_setup (void);
#endif

/*
 * Close the global session, sending an unbind.
 */
static void do_close (ldap_session_t *session);

/*
 * Close the global session without sending an unbind.
 */
static void do_close_no_unbind (ldap_session_t *session);

/*
 * Disable keepalive on a LDAP connection's socket.
 */
static void do_set_sockopts (ldap_session_t *session);

/*
 * TLS routines: set global SSL session options.
 */
#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS) || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int do_ssl_options (ldap_config_t * cfg);
static int do_start_tls (ldap_session_t * session);
#endif

/*
 * Read and validate configuration file.
 * Check current connection state and drop if any of
 *    connection has been snaffled by other software
 *    have forked (thread forked or process forked)
 *    idle time has elapsed since last used
 */
static NSS_STATUS do_check_init (ldap_session_t *session);

/*
 * Read configuration file and initialize schema
 */
static NSS_STATUS do_init (ldap_session_t *session);

/*
 * Open the global session
 */
static NSS_STATUS do_open (ldap_session_t *session);

/*
 * Perform an asynchronous search.
 */
static int do_search (ldap_session_t * session, const char *base, int scope,
		      const char *filter, const char **attrs,
		      int sizelimit, int *);

/*
 * Perform a synchronous search.
 */
static int do_search_s (ldap_session_t * session, const char *base, int scope,
			const char *filter, const char **attrs,
			int sizelimit, LDAPMessage **);

/*
 * Fetch an LDAP result.
 */
static NSS_STATUS do_result (ldap_session_t *session, ent_context_t * ctx, int all);

/*
 * Format a filter given a prototype.
 */
static NSS_STATUS do_filter (const ldap_args_t * args, const char *filterprot,
			     ldap_service_search_descriptor_t * sd,
			     char *filter, size_t filterlen,
			     char **dynamicFilter, const char **retFilter);

/*
 * Parse a result, fetching new results until a successful parse
 * or exceptional condition.
 */
static NSS_STATUS do_parse (ldap_session_t *session, ent_context_t * ctx,
			    void *result, char *buffer,
			    size_t buflen, int *errnop, parser_t parser);

/*
 * Parse a result, fetching results from the result chain 
 * rather than the server.
 */
static NSS_STATUS do_parse_s (ldap_session_t *session, ent_context_t * ctx,
			      void *result, char *buffer,
			      size_t buflen, int *errnop, parser_t parser);

/*
 * Function to be braced by reconnect harness. Used so we
 * can apply the reconnect code to both asynchronous and
 * synchronous searches.
 */
typedef int (*search_func_t) (ldap_session_t *, const char *, int, const char *,
			      const char **, int, void *);

/*
 * Do a search with a reconnect harness.
 */
static NSS_STATUS
do_with_reconnect (ldap_session_t *session, const char *base, int scope,
		   const char *filter, const char **attrs, int sizelimit,
		   void *private, search_func_t func);

/*
 * Map error from LDAP status code to NSS status code
 */
static NSS_STATUS do_map_error (int rc);

/*
 * support the sasl interaction
 */
static int do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *p);

/*
 * Do a sasl bind with a defined timeout
 */
static int do_sasl_bind (ldap_session_t *session, int timelimit, const char *dn, const char *pw);

/*
 * Do a bind with a defined timeout
 */
static int do_bind (ldap_session_t *session, int timelimit, const char *dn, const char *pw,
		    int with_sasl);

static int
do_get_our_socket (ldap_session_t *session, int *sd);

static int
do_dupfd (int oldfd, int newfd);

static void
do_drop_connection (ldap_session_t *session, int sd, int closeSd);

static inline int
__local_option (void *outvalue)
{
  return LDAP_OPT_SUCCESS;
}

/*
 * Define MACROS to handle all of the LDAP options as in-line code
 * rather than conditions all over the package
 * - Howard Wilkinson October 2009
 */
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_DESC)
#define GET_SOCKET_DESCRIPTOR(__conn__, __sd__) \
  (ldap_get_option ((__conn__), LDAP_OPT_DESC, (__sd__)))
#else
#define GET_SOCKET_DESCRIPTOR(__conn__, __sd__) \
  (__local_option (*(__sd__) = (__conn__)->ld_sb.sb_sd))
#endif
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DESC)
#define SET_SOCKET_DESCRIPTOR(__conn__, __sd__) \
  (ldap_set_option ((__conn__), LDAP_OPT_DESC, (__sd__)))
#else
#define SET_SOCKET_DESCRIPTOR(__conn__, __sd__) \
  (__local_option ((__conn__)->ld_sb.sb_sd = *(__sd__)))
#endif

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
#define GET_PROTOCOL_VERSION(__conn__, __version__) \
  (ldap_get_option ((__conn__), LDAP_OPT_PROTOCOL_VERSION, (__version__)))
#else
#define GET_PROTOCOL_VERSION(__conn__, __version__) \
  (__local_option (NULL))
#endif
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
#define SET_PROTOCOL_VERSION(__conn__, __version__) \
  (ldap_set_option ((__conn__), LDAP_OPT_PROTOCOL_VERSION, (__version__)))
#else
#define SET_PROTOCOL_VERSION(__conn__, __version__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_GET_OPTION) &&  defined(LDAP_OPT_ERROR_NUMBER)
#define GET_ERROR_NUMBER(__conn__, __errno__) \
  (ldap_get_option ((__conn__), LDAP_OPT_ERROR_NUMBER, (__errno__)))
#else
#define GET_ERROR_NUMBER(__conn__, __errno__) \
  (__local_option (*(__errno__) = (__conn__)->ld_errno))
#endif

#if defined(HAVE_LDAP_SET_OPTION) &&  defined(LDAP_OPT_ERROR_NUMBER)
#define SET_ERROR_NUMBER(__conn__, __errno__) \
  (ldap_set_option ((__conn__), LDAP_OPT_ERROR_NUMBER, (__errno__)))
#else
#define SET_ERROR_NUMBER(__conn__, __errno__) \
  (__local_option ((__conn__)->ld_errno = *(__errno__))
#endif

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_STRING)
#define GET_ERROR_STRING(__conn__, __errstr__) \
  (ldap_get_option ((__conn__), LDAP_OPT_ERROR_STRING, (__errstr__)))
#else
#define GET_ERROR_STRING(__conn__, __errstr__) \
  (__local_option (*(__errstr__) = (__conn__)->ld_error))
#endif

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_MATCHED_DN)
#define GET_MATCHED_DN(__conn__, __dn__) \
  (ldap_get_option ((__conn__), LDAP_OPT_MATCHED_DN, (__dn__)))
#else
#define GET_MATCHED_DN(__conn__, __dn__) \
  (__local_option (*(__dn__) = (__conn__)->ld_matched))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DEREF)
#define SET_DEREF(__conn__, __deref__) \
  (ldap_set_option ((__conn__), LDAP_OPT_DEREF, (__deref__)))
#else
#define SET_DEREF(__conn__, __dref__) \
  (__local_option ((__conn__)->ld_deref = *(__deref__)))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMELIMIT)
#define SET_TIMELIMIT(__conn__, __timelimit__) \
  (ldap_set_option ((__conn__), LDAP_OPT_TIMELIMIT, (__timelimit__)))
#else
#define SET_TIMELIMIT(__conn__, __timelimit__) \
  (__local_option ((__conn__)->ld_timelimit = *(__timelimit__)))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined (LDAP_OPT_SIZELIMIT)
#define SET_SIZELIMIT(__conn__, __sizelimit__) \
  (ldap_set_option ((__conn__), LDAP_OPT_SIZELIMIT, (__sizelimit__)))
#else
#define SET_SIZELIMIT(__conn__, __sizelimit__) \
  (__local_option ((__conn__)->ld_sizelimit = *(__sizelimit__)))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMEOUT)
#define SET_TIMEOUT(__conn__, __timeout__) \
  (ldap_set_option ((__conn__), LDAP_OPT_TIMEOUT, (__timeout__)))
#else
#define SET_TIMEOUT(__conn__, __timeout__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_X_OPT_CONNECT_TIMEOUT)
  /*
   * This is a new option in the Netscape SDK which sets
   * the TCP connect timeout. For want of a better value,
   * we use the bind_timelimit to control this.
   */
#define SET_CONNECT_TIMEOUT(__conn__, __timeout__) \
  (ldap_set_option ((__conn__), LDAP_X_OPT_CONNECT_TIMEOUT, (__timeout__)))
#else
#define SET_CONNECT_TIMEOUT(__conn__, __timeout__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
#define SET_NETWORK_TIMEOUT(__conn__, __timeout__) \
  (ldap_set_option ((__conn__), LDAP_OPT_NETWORK_TIMEOUT, (__timeout__)))
#else
#define SET_NETWORK_TIMEOUT(__conn__, __timeout__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_REFERRALS)
#define SET_REFERRALS(__conn__, __referrals__) \
  (ldap_set_option ((__conn__), LDAP_OPT_REFERRALS, ((*(__referrals__)) ? LDAP_OPT_ON : LDAP_OPT_OFF)))
#else
#define SET_REFERRALS(__conn__, __referrals__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_RESTART)
#define SET_RESTART(__conn__, __restart__) \
  (ldap_set_option ((__conn__), LDAP_OPT_RESTART, ((*(__restart__)) ? LDAP_OPT_ON : LDAP_OPT_OFF)))
#else
#define SET_RESTART(__conn__, __restart__) \
  (__local_option (NULL))
#endif

/* Support this in Solaris 9 and others than do not define the OPTION macro */
/* not in Solaris 9? */
# ifndef LDAP_OPT_SSL
# define LDAP_OPT_SSL 0x0A
# endif
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_SSL)
#define SET_SSL(__conn__, __ssl__) \
  (ldap_set_option ((__conn__), LDAP_OPT_SSL, ((*(__ssl__)) ? LDAP_OPT_ON : LDAP_OPT_OFF)))
#else
#define SET_SSL(__conn__, __ssl__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
#define SET_TLS(__conn__, __tls__) \
  (ldap_set_option ((__conn__), LDAP_OPT_X_TLS, (__tls__)))
#else
#define SET_TLS(__conn__, __tls__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_RANDOM_FILE)
#define SET_TLS_RANDOM_FILE(__conn__, __randomfile__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_RANDOM_FILE, (__randomfile__)))
#else
#define SET_TLS_RANDOM_FILE(__conn__, __randfile) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_CACERTFILE)
#define SET_TLS_CACERTFILE(__conn__, __cacertfile__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, (__cacertfile__)))
#else
#define SET_TLS_CACERTFILE(__conn__, __certfile__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_CACERTDIR)
#define SET_TLS_CACERTDIR(__conn__, __cacertdir__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR, (__cacertdir__)))
#else
#define SET_TLS_CACERTDIR(__conn__, __cacertdir__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_REQUIRE_CERT)
#define SET_TLS_REQUIRE_CERT(__conn__, __checkpeer__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, (__checkpeer__)))
#else
#define SET_TLS_REQUIRE_CERT(__conn__, __checkpeer__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_CIPHER_SUITE)
#define SET_TLS_CIPHER_SUITE(__conn__, __ciphers__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, (__ciphers__)))
#else
#define SET_TLS_CIPHER_SUITE(__conn__, __ciphersuite__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_CERTFILE)
#define SET_TLS_CERTFILE(__conn__, __certfile__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, (__certfile__)))
#else
#define SET_TLS_CERTFILE(__conn__, __certfile__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS_KEYFILE)
#define SET_TLS_KEYFILE(__conn__, __keyfile__) \
  (ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, (__keyfile__)))
#else
#define SET_TLS_KEYFILE(__conn_, __keyfile__) \
  (__local_option (NULL))
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_SASL_SECPROPS)
#define SET_SASL_SECPROPS(__conn__, __sasl_secprops__)				\
  (ldap_set_option ((__conn__), LDAP_OPT_X_SASL_SECPROPS, (__sasl_secprops__)))
#else
#define SET_SASL_SECPROPS(__conn__, __sasl_secprops__) \
  (__local_option (NULL))
#endif

const char *
__nss_ldap_status2string (NSS_STATUS stat)
{
  switch (stat)
    {
    case NSS_TRYAGAIN:	return "NSS_TRYAGAIN";
    case NSS_UNAVAIL:	return "NSS_UNAVAIL";
    case NSS_NOTFOUND:	return "NSS_NOTFOUND";
    case NSS_SUCCESS:	return "NSS_SUCCESS";
    case NSS_RETURN:	return "NSS_RETURN";
    default:		return "UNKNOWN";
    }
}

static NSS_STATUS
do_map_error (int rc)
{
  NSS_STATUS stat;

  switch (rc)
    {
    case LDAP_SUCCESS:
    case LDAP_SIZELIMIT_EXCEEDED:
    case LDAP_TIMELIMIT_EXCEEDED:
      stat = NSS_SUCCESS;
      break;
    case LDAP_NO_SUCH_ATTRIBUTE:
    case LDAP_UNDEFINED_TYPE:
    case LDAP_INAPPROPRIATE_MATCHING:
    case LDAP_CONSTRAINT_VIOLATION:
    case LDAP_TYPE_OR_VALUE_EXISTS:
    case LDAP_INVALID_SYNTAX:
    case LDAP_NO_SUCH_OBJECT:
    case LDAP_ALIAS_PROBLEM:
    case LDAP_INVALID_DN_SYNTAX:
    case LDAP_IS_LEAF:
    case LDAP_ALIAS_DEREF_PROBLEM:
    case LDAP_FILTER_ERROR:
      stat = NSS_NOTFOUND;
      break;
    case LDAP_SERVER_DOWN:
    case LDAP_TIMEOUT:
    case LDAP_UNAVAILABLE:
    case LDAP_BUSY:
#ifdef LDAP_CONNECT_ERROR
    case LDAP_CONNECT_ERROR:
#endif /* LDAP_CONNECT_ERROR */
      stat = NSS_TRYAGAIN;
      break;
    case LDAP_LOCAL_ERROR:
    case LDAP_INVALID_CREDENTIALS:
    default:
      stat = NSS_UNAVAIL;
      break;
    }
  return stat;
}

/*
 * Rebind functions.
 */

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_rebind (LDAP * ld, LDAP_CONST char *url, ber_tag_t request,
	   ber_int_t msgid, void *arg)
#else
static int
do_rebind (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid)
#endif
{
  char *who = NULL, *cred = NULL;
  int timelimit;
  int with_sasl = 0;
  uid_t euid;
  ldap_config_t *cfg;
  ldap_session_t *session = &__session;
  int rc;

  debug ("==> do_rebind");

  cfg = session->ls_config;

  euid = geteuid ();

  if (euid == 0)
    {
      who = (cfg->ldc_rootbinddn != NULL) ? cfg->ldc_rootbinddn : cfg->ldc_binddn;
      with_sasl = (cfg->ldc_rootsaslid != NULL) ? cfg->ldc_rootusesasl : cfg->ldc_usesasl;
      if (with_sasl)
	{
	  cred = (cfg->ldc_rootsaslid != NULL) ? cfg->ldc_rootsaslid : cfg->ldc_saslid;
	}
      else
	{
	  cred = (cfg->ldc_rootbindpw != NULL) ? cfg->ldc_rootbindpw : cfg->ldc_bindpw;
	}
    }
  else
    {
      who = cfg->ldc_binddn;
      with_sasl = cfg->ldc_usesasl;
      if (with_sasl)
	{
	  cred = cfg->ldc_saslid;
	}
      else
	{
	  cred = cfg->ldc_bindpw;
	}
    }

  timelimit = cfg->ldc_bind_timelimit;

#ifdef HAVE_LDAP_START_TLS_S
  if (cfg->ldc_ssl_on == SSL_START_TLS)
    {
      int version;

      if (GET_PROTOCOL_VERSION (session->ls_conn, &version) == LDAP_OPT_SUCCESS)
	{
	  if (version < LDAP_VERSION3)
	    {
	      version = LDAP_VERSION3;
	      SET_PROTOCOL_VERSION (session->ls_conn, &version);
	    }
	}

      if (do_start_tls (session) == LDAP_SUCCESS)
	{
	  debug ("TLS startup succeeded");
	}
      else
	{
	  debug ("TLS startup failed");
	  return NSS_UNAVAIL;
	}
    }
#endif /* HAVE_LDAP_START_TLS_S */

  rc = do_bind (session, timelimit, with_sasl ? cred : who, with_sasl ? NULL : cred, with_sasl);

  debug ("<== do_rebind");

  return rc;
}
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
	   int freeit, void *arg)
#elif LDAP_SET_REBIND_PROC_ARGS == 2
static int
do_rebind (LDAP * ld, char **whop, char **credp, int *methodp, int freeit)
#endif
{
  uid_t euid;
  ldap_config_t *cfg;
  ldap_session_t *session = &__session;

  debug ("==> do_rebind");

  cfg = session->ls_config;

  euid = geteuid ();

  if (freeit != 0)
    {
      if (*whop != NULL)
	free (*whop);
      if (*credp != NULL)
	free (*credp);
    }

  /*
   * If we are running as root and we have a root binddn
   * then use the root binddn and root bindpw
   * (use the ordinary bindpw if a root one has not been provided)
   */
  if (euid == 0 && cfg->ldc_rootbinddn != NULL)
    {
      *whop = strdup(cfg->ldc_rootbinddn);
      *credp = ((cfg->ldc_rootbindpw != NULL)
		? strdup (cfg->ldc_rootbindpw)
		: ((cfg->ldc_bindpw != NULL)
		   ? strdup (cfg->ldc_bindpw)
		   : NULL));
    }
  /*
   * If not running as root
   * then use the base binddn and the bindpw (if supplied)
   */
  else if (cfg->ldc_binddn != NULL)
    {
      *whop = strdup (cfg->ldc_binddn);
      *credp = ((cfg->ldc_bindpw != NULL)
		? strdup (cfg->ldc_bindpw)
		: NULL);
    }
  else
    {
      *whop = NULL;
      *credp = NULL;
    }

  *methodp = LDAP_AUTH_SIMPLE;

  debug ("<== do_rebind");

  return LDAP_SUCCESS;
}
#endif

#ifdef HAVE_NSSWITCH_H
/*
 * Default destructor.
 * The entry point for this function is the destructor in the dispatch
 * table for the switch. Thus, it's safe to grab the mutex from this
 * function.
 */
NSS_STATUS
_nss_ldap_default_destr (nss_backend_t * be, void *args)
{
  debug ("==> _nss_ldap_default_destr");

  if ((((nss_ldap_backend_t *) be)->state) != NULL)
    {
      _nss_ldap_enter ();
      _nss_ldap_ent_context_release (&(((nss_ldap_backend_t *) be)->state));
      _nss_ldap_leave ();
    }

  /* Ditch the backend. */
  free (be);

  debug ("<== _nss_ldap_default_destr");

  return NSS_SUCCESS;
}

/*
 * This is the default "constructor" which gets called from each 
 * constructor, in the NSS dispatch table.
 */
NSS_STATUS
_nss_ldap_default_constr (nss_ldap_backend_t * be)
{
  debug ("==> _nss_ldap_default_constr");

  be->state = NULL;
#ifdef HPUX
  __thread_mutex_init (&__lock, NULL);
#endif

  debug ("<== _nss_ldap_default_constr");

  return NSS_SUCCESS;
}
#endif /* HAVE_NSSWITCH_H */

#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
static void
do_atfork_prepare (void)
{
  debug ("==> do_atfork_prepare");
  _nss_ldap_enter ();
  debug ("<== do_atfork_prepare");
}

static void
do_atfork_parent (void)
{
  debug ("==> do_atfork_parent");
  _nss_ldap_leave ();
  debug ("<== do_atfork_parent");
}

static void
do_atfork_child (void)
{
  ldap_session_t *session = &__session;
  sigset_t unblock, mask;

  debug ("==> do_atfork_child");

  sigemptyset(&unblock);
  sigaddset(&unblock, SIGPIPE);
  sigprocmask(SIG_UNBLOCK, &unblock, &mask);
  do_close_no_unbind (session);
  sigprocmask(SIG_SETMASK, &mask, NULL);

  _nss_ldap_leave ();
  debug ("<== do_atfork_child");
}

static void
do_atfork_setup (void)
{
  debug ("==> do_atfork_setup");
  (void) ATFORK_DO (do_atfork_prepare, do_atfork_parent, do_atfork_child);
  debug ("<== do_atfork_setup");
}

static NSS_STATUS
do_thread_once()
{
  debug ("==> do_thread_once");
#if defined(HAVE_PTHREAD_ONCE) && defined(HAVE_PTHREAD_ATFORK)
  if (pthread_once (&__once, do_atfork_setup) != 0)
    {
      debug ("<== do_thread_once (pthread_once failed)");
      return NSS_UNAVAIL;
    }
#elif defined(HAVE_PTHREAD_ATFORK) && ( defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H) )
  __libc_once (__once, do_atfork_setup);
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  /*
   * Only install the pthread_atfork() handlers if
   * we are linked against libpthreads. Otherwise,
   * do close the session when the PID changes.
   */
  if !(__pthread_once == NULL || __pthread_atfork == NULL)
    __libc_once (__once, do_atfork_setup);
#endif

  debug ("<== do_thread_once");

  return NSS_SUCCESS;
}

static int
pthreading_active(void)
{
#if defined(HAVE_PTHREAD_ATFORK)
  return 1;
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  return (__pthread_once != NULL &&__pthread_atfork != NULL && __once != PTHREAD_ONCE_INIT);
#else
  return 0;
#endif
}
#endif

/*
 * Acquires global lock, blocks SIGPIPE.
 */
void
_nss_ldap_enter (void)
{

#ifdef HAVE_SIGACTION
  struct sigaction new_handler;

  memset (&new_handler, 0, sizeof (new_handler));
#if 0
  /* XXX need to test for sa_sigaction, not on all platforms */
  new_handler.sa_sigaction = NULL;
#endif
  new_handler.sa_handler = SIG_IGN;
  sigemptyset (&new_handler.sa_mask);
  new_handler.sa_flags = 0;
#endif /* HAVE_SIGACTION */

  debug ("==> _nss_ldap_enter");

  NSS_LDAP_LOCK (__lock);

  /*
   * Patch for Debian Bug 130006:
   * ignore SIGPIPE for all LDAP operations.
   * 
   * The following bug was reintroduced in nss_ldap-213 and is fixed here:
   * http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=84344
   *
   * See:
   * http://www.gnu.org/software/libc/manual/html_node/Signal-and-Sigaction.html
   * for more details.
   */
#ifdef HAVE_SIGACTION
  __sigaction_retval = sigaction (SIGPIPE, &new_handler, &__stored_handler);
#elif defined(HAVE_SIGSET)
  __sigpipe_handler = sigset (SIGPIPE, SIG_IGN);
#else
  __sigpipe_handler = signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */

  debug ("<== _nss_ldap_enter");

  return;
}

/*
 * Releases global mutex, releases SIGPIPE.
 */
void
_nss_ldap_leave (void)
{
  debug ("==> _nss_ldap_leave");

#ifdef HAVE_SIGACTION
  if (__sigaction_retval == 0)
    (void) sigaction (SIGPIPE, &__stored_handler, NULL);
#else
  if (__sigpipe_handler != SIG_ERR && __sigpipe_handler != SIG_IGN)
    {
# ifdef HAVE_SIGSET
      (void) sigset (SIGPIPE, __sigpipe_handler);
# else
      (void) signal (SIGPIPE, __sigpipe_handler);
# endif	/* HAVE_SIGSET */
    }
#endif /* HAVE_SIGACTION */

  NSS_LDAP_UNLOCK (__lock);

  debug ("<== _nss_ldap_leave");

  return;
}

static void
do_set_sockopts (ldap_session_t *session)
{
/*
 * Netscape SSL-enabled LDAP library does not
 * return the real socket.
 */
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  int sd = -1;

  debug ("==> do_set_sockopts");

  if ((GET_SOCKET_DESCRIPTOR (session->ls_conn, &sd) == LDAP_OPT_SUCCESS) && (sd > 0))
    {
      int off = 0;
      NSS_LDAP_SOCKLEN_T socknamelen = sizeof (NSS_LDAP_SOCKADDR_STORAGE);
      NSS_LDAP_SOCKLEN_T peernamelen = sizeof (NSS_LDAP_SOCKADDR_STORAGE);

      (void) setsockopt (sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &off,
			 sizeof (off));
      (void) fcntl (sd, F_SETFD, FD_CLOEXEC);
      /*
       * NSS modules shouldn't open file descriptors that the program/utility
       * linked against NSS doesn't know about.  The LDAP library opens a
       * connection to the LDAP server transparently.  There's an edge case
       * where a daemon might fork a child and, being written well, closes
       * all its file descriptors.  This will close the socket descriptor
       * being used by the LDAP library!  Worse, the daemon might open many
       * files and sockets, eventually opening a descriptor with the same number
       * as that originally used by the LDAP library.  The only way to know that
       * this isn't "our" socket descriptor is to save the local and remote
       * sockaddr_in structures for later comparison.
       */
      (void) getsockname (sd, (struct sockaddr *) &(session->ls_sockname),
			  &socknamelen);
      (void) getpeername (sd, (struct sockaddr *) &(session->ls_peername),
			  &peernamelen);
    }
  debug ("<== do_set_sockopts");
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

  return;
}

static void
do_close_mechs (ldap_session_t *session)
{
  debug ("==> do_close_mechs");

  /* Close any active sasl mechanisms */
  if (session->ls_mechs != NULL)
    {
      int i;

      for (i = 0; i < session->ls_mechs->lsms_count; i++)
	{
	  session->ls_mechs->lsms_mechs[i]->lsm_close (session);
	}
    }

  debug ("<== do_close_mechs");
}

/*
 * Closes connection to the LDAP server.
 * This assumes that we have exclusive access to __session.ls_conn,
 * either by some other function having acquired a lock, or by
 * using a thread safe libldap.
 */
static void
do_close (ldap_session_t *session)
{
  debug ("==> do_close");

  do_close_mechs (session);

  if (session->ls_conn != NULL)
    {
#if defined(DEBUG) || defined(DEBUG_SOCKETS)
      int sd = -1;
      GET_SOCKET_DESCRIPTOR (session->ls_conn, &sd);
      syslog (LOG_INFO, "nss_ldap: closing connection %p fd %d",
	      session->ls_conn, sd);
#endif /* DEBUG */

      ldap_unbind (session->ls_conn);
      session->ls_conn = NULL;
      session->ls_state = LS_UNINITIALIZED;
    }

  debug ("<== do_close");
}

static int
do_sockaddr_isequal (NSS_LDAP_SOCKADDR_STORAGE *_s1,
		     NSS_LDAP_SOCKLEN_T _slen1,
		     NSS_LDAP_SOCKADDR_STORAGE *_s2,
		     NSS_LDAP_SOCKLEN_T _slen2)
{
  int ret;

  if (_s1->ss_family != _s2->ss_family)
    return 0;

  if (_slen1 != _slen2)
    return 0;

  ret = 0;

  switch (_s1->ss_family)
    {
      case AF_INET:
	{
	  struct sockaddr_in *s1 = (struct sockaddr_in *) _s1;
	  struct sockaddr_in *s2 = (struct sockaddr_in *) _s2;

	  ret = (s1->sin_port == s2->sin_port &&
		 memcmp (&s1->sin_addr, &s2->sin_addr, sizeof(struct in_addr)) == 0);
	  break;
	}
      case AF_UNIX:
	{
	  struct sockaddr_un *s1 = (struct sockaddr_un *) _s1;
	  struct sockaddr_un *s2 = (struct sockaddr_un *) _s2;

	  ret = (memcmp (s1->sun_path, s2->sun_path,
			 _slen1 - sizeof (_s1->ss_family)) == 0);
	  break;
	}
#ifdef INET6
      case AF_INET6:
	{
	  struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) _s1;
	  struct sockaddr_in6 *s2 = (struct sockaddr_in6 *) _s2;

	  ret = (s1->sin6_port == s2->sin6_port &&
		 memcmp (&s1->sin6_addr, &s2->sin6_addr, sizeof (struct in6_addr)) == 0 &&
		 s1->sin6_scope_id == s2->sin6_scope_id);
	  break;
	}
#endif
      default:
	ret = (memcmp (_s1, _s2, _slen1) == 0);
	break;
    }

  return ret;
}

static int
do_get_our_socket (ldap_session_t *session, int *sd)
{
  /*
   * Before freeing the LDAP context or closing the socket descriptor,
   * we must ensure that it is *our* socket descriptor.  See the much
   * lengthier description of this at the end of do_open () where the
   * values __session.ls_sockname and __session.ls_peername are saved.
   * With HAVE_LDAPSSL_CLIENT_INIT this returns 0 if the socket has
   * been closed or reopened, and sets *sd to the ldap socket
   * descriptor.. Returns 1 in all other cases.
   */

  int isOurSocket = 1;

#ifndef HAVE_LDAPSSL_CLIENT_INIT
  if ((GET_SOCKET_DESCRIPTOR (session->ls_conn, sd) == LDAP_OPT_SUCCESS) && (*sd > 0))
    {
      NSS_LDAP_SOCKADDR_STORAGE sockname;
      NSS_LDAP_SOCKADDR_STORAGE peername;
      NSS_LDAP_SOCKLEN_T socknamelen = sizeof (sockname);
      NSS_LDAP_SOCKLEN_T peernamelen = sizeof (peername);

      if (getsockname (*sd, (struct sockaddr *) &sockname, &socknamelen) != 0 ||
	  !do_sockaddr_isequal (&(session->ls_sockname),
				socknamelen,
				&sockname,
				socknamelen))
        {
          isOurSocket = 0;
        }
      /*
       * XXX: We don't pay any attention to return codes in places such as
       * do_search_s so we never observe when the other end has disconnected
       * our socket.  In that case we'll get an ENOTCONN error here... and
       * it's best we ignore the error -- otherwise we'll leak a filedescriptor.
       * The correct fix would be to test error codes in many places.
       */
      else if (getpeername (*sd, (struct sockaddr *) &peername, &peernamelen) != 0)
	{
          if (errno != ENOTCONN)
            isOurSocket = 0;
	}
      else
	{
          isOurSocket = do_sockaddr_isequal (&(session->ls_peername),
                                              peernamelen,
                                              &peername,
                                              peernamelen);
	}
    }
#endif /* HAVE_LDAPSSL_CLIENT_INIT */
  return isOurSocket;
}

static int
do_dupfd (int oldfd, int newfd)
{
  int d = -1;
  int flags;

  flags = fcntl (oldfd, F_GETFD);

  while (1)
    {
      d = (newfd > -1) ? dup2 (oldfd, newfd) : dup (oldfd);
      if (d > -1)
	break;

      if (errno == EBADF)
	return -1; /* not open */

      if (errno != EINTR
#ifdef EBUSY
	    && errno != EBUSY
#endif
	    )
	return -1;
  }

  /* duplicate close-on-exec flag */
  (void) fcntl (d, F_SETFD, flags);

  return d;
}

static int
do_closefd (int fd)
{
  int rc;

  while ((rc = close(fd)) < 0 && errno == EINTR)
    ;

  return rc;
}

static void
do_drop_connection (ldap_session_t *session, int sd, int closeSd)
{
     /* Close the LDAP connection without writing anything to the
	underlying socket.  The socket will be left open afterwards if
	closeSd is 0 */
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  {
    int dummyfd = -1, savedfd = -1;
    /*  Under OpenLDAP 2.x, ldap_set_option (..., LDAP_OPT_DESC, ...) is
	a no-op, so to shut down the LDAP connection without writing
	anything to the socket, we swap a dummy socket onto that file
	descriptor, and then swap the real fd back once the shutdown is
	done. */
    savedfd = do_dupfd (sd, -1);
    dummyfd = socket (AF_INET, SOCK_STREAM, 0);
    if (dummyfd > -1 && dummyfd != sd)
      {
        /* we must let dup2 close sd for us to avoid race conditions
         * in multithreaded code.
         */
	do_dupfd (dummyfd, sd);
	do_closefd (dummyfd);
      }

#ifdef HAVE_LDAP_LD_FREE
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
    /* XXX: when using openssl this will *ALWAYS* close the fd */
    (void) ldap_ld_free (session->ls_conn, 0, NULL, NULL);
#else
    (void) ldap_ld_free (session->ls_conn, 0);
#endif /* OPENLDAP 2.x */
#else
    ldap_unbind (session->ls_conn);
#endif /* HAVE_LDAP_LD_FREE */

    /* Do we want our original sd back? */
    if (savedfd > -1)
      {
	if (closeSd == 0)
	  do_dupfd (savedfd, sd);
        else
          do_closefd (sd);
	do_closefd (savedfd);
      }
    else
      {
        do_closefd (sd);
      }
  }
#else /* No sd available */
  {
    int bogusSd = -1;
    if (closeSd == 0)
      {
	sd = -1; /* don't want to really close the socket */
#ifdef HAVE_LDAP_LD_FREE
	SET_SOCKET_DESCRIPTOR (session->ls_conn, &sd);
#endif /* HAVE_LDAP_LD_FREE */
      }

#ifdef HAVE_LDAP_LD_FREE

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
    (void) ldap_ld_free (session->ls_conn, 0, NULL, NULL);
#else
    (void) ldap_ld_free (session->ls_conn, 0);
#endif /* OPENLDAP 2.x */
    
#else

    SET_SOCKET_DESCRIPTOR (session->ls_conn, &bogusSd);

    /* hope we closed it OK! */
    ldap_unbind (session->ls_conn);

#endif /* HAVE_LDAP_LD_FREE */
    
  }
#endif /* HAVE_LDAPSSL_CLIENT_INIT */
  session->ls_conn = NULL;
  session->ls_state = LS_UNINITIALIZED;

  return;
}

/*
 * If we've forked, then we need to open a new session.
 * Careful: we have the socket shared with our parent,
 * so we don't want to send an unbind to the server.
 * However, we want to close the descriptor to avoid
 * leaking it, and we also want to release the memory
 * used by __session.ls_conn. The only entry point
 * we have is ldap_unbind() which does both of these
 * things, so we use an internal API, at the expense
 * of compatibility.
 */
static void
do_close_no_unbind (ldap_session_t * session)
{
  int sd = -1;
  int closeSd = 1;

  debug ("==> do_close_no_unbind");

  do_close_mechs (session);

  if (session->ls_state == LS_UNINITIALIZED)
    {
      assert (session->ls_conn == NULL);
      debug ("<== do_close_no_unbind (connection was not open)");
      return;
    }

  closeSd = do_get_our_socket (session, &sd);

#if defined(DEBUG) || defined(DEBUG_SOCKETS)
  syslog (LOG_INFO, "nss_ldap: %sclosing connection (no unbind) %p fd %d",
	  closeSd ? "" : "not ", session->ls_conn, sd);
#endif /* DEBUG */

  do_drop_connection (session, sd, closeSd);

  debug ("<== do_close_no_unbind");

  return;
}

/*
 * A simple alias around do_init().
 */
NSS_STATUS
_nss_ldap_init (void)
{
  ldap_session_t *session = &__session;
  NSS_STATUS stat;

  debug ("==> _nss_ldap_init");

  stat = do_check_init (session);
  if (stat != NSS_SUCCESS)
    {
      stat = do_init (session);
    }

  debug ("<== _nss_ldap_init: returns %s(%d)", __nss_ldap_status2string(stat), stat);

  return stat;
}

/*
 * A simple alias around do_close().
 */
void
_nss_ldap_close (void)
{
  do_close (&__session);
}

static void
_nss_ldap_res_init (const char *uri)
{
  if (strncmp (uri, "ldapi://", 8) != 0)
    {
      struct stat st;
      static time_t last_mtime = (time_t) -1;
#if defined(HAVE_RESOLV_H) && defined(_PATH_RESCONF)
      NSS_LDAP_DEFINE_LOCK (_nss_ldap_res_init_lock);
      NSS_LDAP_LOCK (_nss_ldap_res_init_lock);
      if (stat (_PATH_RESCONF, &st) == 0)
        {
          if (last_mtime != st.st_mtime)
            {
              last_mtime = st.st_mtime;
              res_init ();
            }
        }
      NSS_LDAP_UNLOCK (_nss_ldap_res_init_lock);
#endif
    }
}

static NSS_STATUS
do_init_session (ldap_session_t  *session, const char *uri, int defport)
{
  int rc;
  int ldaps, i;
  char uribuf[NSS_BUFSIZ];
  char *p;
  NSS_STATUS stat;

  debug ("==> do_init_session");

  ldaps = (strncasecmp (uri, "ldaps://", sizeof ("ldaps://") - 1) == 0);
  p = strchr (uri, ':');
  /* we should be looking for the second instance to find the port number */
  if (p != NULL)
    {
      p = strchr (++p, ':');
    }

  if (session->ls_mechs != NULL)
    {
      for (i = 0; i < session->ls_mechs->lsms_count; i++)
	{
	  session->ls_mechs->lsms_mechs[i]->lsm_init (session);
	}
    }

  _nss_ldap_res_init (uri);

#ifdef HAVE_LDAP_INITIALIZE
  if (p == NULL && defport != 0 &&
      ((ldaps && defport != LDAPS_PORT) || (!ldaps && defport != LDAP_PORT)))
    {
      /* No port specified in URI and non-default port specified */
      snprintf (uribuf, sizeof (uribuf), "%s:%d", uri, defport);
      uri = uribuf;
    }

  _nss_ldap_res_init(uri);

  rc = ldap_initialize (&session->ls_conn, uri);
#else
  if (strncasecmp (uri, "ldap://", sizeof ("ldap://") - 1) != 0)
    {
      return NSS_UNAVAIL;
    }

  uri += sizeof ("ldap://") - 1;
  p = strchr (uri, ':');

  if (p != NULL)
    {
      size_t urilen = (p - uri);

      if (urilen >= sizeof (uribuf))
	{
	  return NSS_UNAVAIL;
	}

      memcpy (uribuf, uri, urilen);
      uribuf[urilen] = '\0';

      defport = atoi (p + 1);
      uri = uribuf;
    }

  _nss_ldap_res_init(NULL);
# ifdef HAVE_LDAP_INIT
  session->ls_conn = ldap_init (uri, defport);
# else
  session->ls_conn = ldap_open (uri, defport);
# endif

  rc = (session->ls_conn == NULL) ? LDAP_SERVER_DOWN : LDAP_SUCCESS;

#endif /* HAVE_LDAP_INITIALIZE */

  stat = do_map_error (rc);
  if (stat == NSS_SUCCESS && session->ls_conn == NULL)
    {
      stat = NSS_UNAVAIL;
    }

  debug ("<== do_init_session");

  return stat;
}

static void
do_check_threading (ldap_session_t *session)
{
  pid_t pid = -1;
  uid_t euid = -1;
  
  debug ("==> do_check_threading");
  
#if defined(HAVE_PTHREAD_ATFORK)
  /*
   * Definitely linked against the pthread library if we are using
   * pthread_atfork
   */
#else
# if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  /*
   * This bogosity is necessary because Linux uses different
   * PIDs for different threads (like IRIX, which we don't
   * support). We can tell whether we are linked against
   * libpthreads by whether __pthread_once is NULL or
   * not. If it is NULL, then we're not linked with the
   * threading library, and we need to compare the current
   * process ID against the saved one to figure out
   * whether we've forked. 
   *
   * --
   *  __pthread_once does not imply __pthread_atfork being non-NULL!
   *  <tjanouse@redhat.com>
   * --
   * 
   * Once we know whether we have forked or not, 
   * courtesy of pthread_atfork() or us checking
   * ourselves, we can close the socket to the LDAP
   * server to avoid leaking a socket, and reopen
   * another connection. Under no circumstances do we
   * wish to use the same connection, or to send an
   * unbind PDU over the parents connection, as that
   * will wreak all sorts of havoc or inefficiencies,
   * respectively.
   */
  if (__pthread_once == NULL || __pthread_atfork == NULL)
    pid = getpid ();
# else
  pid = getpid ();
# endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
#endif /* HAVE_PTHREAD_ATFORK */

  euid = geteuid ();

#ifdef DEBUG
# if defined(HAVE_PTHREAD_ATFORK)
  syslog (LOG_DEBUG,
	  "nss_ldap: session->ls_state=%d, session->ls_conn=%p, session euid=%i, current euid=%i",
	  session->ls_state, session->ls_conn, session->euid, euid);
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  syslog (LOG_DEBUG,
	  "nss_ldap: libpthreads=%s, session->ls_state=%d, session->ls_conn=%p, session pid=%i, current pid=%i, session euid=%i, current euid=%i",
 	  ((__pthread_once == NULL || __pthread_atfork == NULL) ? "FALSE" : "TRUE"),
	  session->ls_state,
	  session->ls_conn,
 	  ((__pthread_once == NULL || __pthread_atfork == NULL) ? session->pid : -1),
 	  ((__pthread_once == NULL || __pthread_atfork == NULL) ? pid : -1), session->euid, euid);
#else
  syslog (LOG_DEBUG,
	  "nss_ldap: session->ls_state=%d, session->ls_conn=%p, session pid=%i, current pid=%i, session euid=%i, current euid=%i",
	  session->ls_state, session->ls_conn, session->pid, pid, session->euid, euid);
#endif
#endif /* DEBUG */

  debug (":== do_check_threading pthreading=%d, session pid=%d, pid=%d",
	 pthreading_active(), session->pid, pid);
  assert ((pthreading_active() && (session->pid == -1) && (pid == -1))
	  || (!pthreading_active() && ((session->pid != -1) || (pid != -1))));

  session->pid = pid;
  session->euid = euid;

  debug ("<== do_check_threading");
}

static NSS_STATUS
do_check_init (ldap_session_t *session)
{
  int sd = -1;
  NSS_STATUS stat = NSS_UNAVAIL;
  pid_t pid;
  uid_t euid;

  debug ("==> do_check_init");

  /* Check that the config is (still) valid */
  stat = _nss_ldap_validateconfig (session->ls_config);
  if (stat == NSS_TRYAGAIN)
    {
      /* Config has changed close old session */
      do_close (session);
      session->ls_config = NULL;
      session->ls_current_uri = -1;
    }

  /* If we have no config then the connection should never have been made */
  if (stat == NSS_UNAVAIL)
    {
      assert(session->ls_conn == NULL && session->ls_state == LS_UNINITIALIZED);
    }

  /* Check current state of threading */
  pid = session->pid;
  euid = session->euid;

  do_check_threading (session);

  debug (":== do_check_init: session pid=%d, current pid=%d, session euid=%d, current euid=%d",
	 pid, session->pid, euid, session->euid);

  if (session->ls_state == LS_CONNECTED_TO_DSA &&
      do_get_our_socket (session, &sd) == 0)
    {
      /* The calling app has stolen our socket. */
      debug (":== do_check_init (stolen socket detected)");
      do_drop_connection (session, sd, 0);
    }
  else if (pid != session->pid) /* These are both -1 if the threading is active and using pthread_atfork */
    {
      debug (":== do_check_init: thread id changed");
      do_close_no_unbind (session);
    }
  else if (euid != session->euid && (euid == 0 || session->euid == 0))
    {
      /*
       * If we've changed user ids, close the session so we can
       * rebind as the correct user. - Why only root?
       */
      debug (":== do_check_init: effective uid changed");
      do_close (session);
    }
#ifdef notdef
  else if (session->ls_state == LS_CONNECTED_TO_DSA)
    {
      time_t current_time;

      /*
       * Otherwise we can hand back this process' global
       * LDAP session.
       *
       * Patch from Steven Barrus <sbarrus@eng.utah.edu> to
       * close the session after an idle timeout. 
       */

      assert (session->ls_conn != NULL);
      assert (session->ls_config != NULL);

      if (session->ls_config->ldc_idle_timelimit != 0)
	{
	  time (&current_time);
	  if ((session->ls_timestamp +
	       session->ls_config->ldc_idle_timelimit) < current_time)
	    {
	      debug (":== do_checkinit: idle_timelimit reached");
	      do_close (session);
	    }
	}
    }
#endif

  /*
   * If the connection is still there (ie. do_close() wasn't
   * called) then we can return the cached connection.
   */
  if (session->ls_state == LS_CONNECTED_TO_DSA
      || session->ls_state == LS_INITIALIZED)
    {
      debug ("<== do_check_init: cached session");
      return NSS_SUCCESS;
    }
  else
    {
      debug ("<== do_check_init: no cached session");
      return NSS_UNAVAIL;
    }
}

static void
do_init_mechs (ldap_session_t *session)
{
  ldap_session_mechs_t mechs = session->ls_mechs;
  int i, mechCount = 0;

  debug ("==> do_init_mechs");

  /*
   * Initialise the mechs
   */
  if (mechs != NULL)
    {
      mechCount = mechs->lsms_count;

      for (i = 0; i < mechCount; i++)
	{
	  ldap_session_mech_t mech = session->ls_mechs->lsms_mechs[i];

	  if (mech != NULL)
	    {
	      if (mech->lsm_close != NULL)
		{
		  mech->lsm_close (session);
		}
	      free(mech);
	    }
	}
      free (mechs);
      session->ls_mechs = mechs = NULL;
    }

  mechCount = sizeof (sasl_setups) / sizeof (ldap_session_mech_setup_t);
  if (mechCount == 0)
    {
      return;
    }

  mechs = (ldap_session_mechs_t)malloc (sizeof (*mechs) + sizeof (ldap_session_mech_setup_t) * mechCount);
  for (i = 0; i < mechCount; i++)
    {
      mechs->lsms_mechs[i] = sasl_setups[i] ();
    }
  mechs->lsms_count = mechCount;

  session->ls_mechs = mechs;

  debug ("<== do_init_mechs");

  return;
}

/*
 * Mutex must be held when entering and leaving this code
 */
static NSS_STATUS
do_init (ldap_session_t *session)
{
  ldap_config_t *cfg;
  NSS_STATUS stat;

  debug ("==> do_init");

  session->ls_conn = NULL;
  session->ls_timestamp = 0;
  session->ls_state = LS_UNINITIALIZED;

  stat = do_thread_once ();
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  /* Initialize schema and LDAP handle (but do not connect) */
  if (session->ls_config == NULL)
    {
      char *configbufp = __configbuf;
      size_t configbuflen = sizeof (__configbuf);

      stat = _nss_ldap_readconfig (&(session->ls_config), &configbufp, &configbuflen);
      if (stat == NSS_NOTFOUND)
	{
	  /* Config was read but no host information specified; try DNS */
	  stat = _nss_ldap_mergeconfigfromdns (session->ls_config, &configbufp, &configbuflen);
	  if (stat != NSS_SUCCESS)
	    {
      	      syslog (LOG_ERR, "nss_ldap: could not determine LDAP server from ldap.conf or DNS");
	    }
	}

      if (stat != NSS_SUCCESS)
	{
	  debug ("<== do_init (failed to read config)");
 	  session->ls_config = NULL;
	  return NSS_UNAVAIL;
	}
      session->ls_current_uri = 0;
    }

  cfg = session->ls_config;

  _nss_ldap_init_attributes (cfg->ldc_attrtab, (cfg->ldc_flags & NSS_LDAP_FLAGS_GETGRENT_SKIPMEMBERS) != 0);
  _nss_ldap_init_filters ();

#ifdef HAVE_LDAP_SET_OPTION
  if (cfg->ldc_debug != 0)
    {
# ifdef LBER_OPT_LOG_PRINT_FILE
      if (cfg->ldc_logdir != NULL && __debugfile == NULL)
	{
	  char namebuf[PATH_MAX];

	  snprintf (namebuf, sizeof (namebuf), "%s/ldap.%d", cfg->ldc_logdir,
		    (int) getpid ());
	  __debugfile = fopen (namebuf, "a");

	  if (__debugfile != NULL)
	    {
	      ber_set_option (NULL, LBER_OPT_LOG_PRINT_FILE, __debugfile);
	    }
	}
# endif	/* LBER_OPT_LOG_PRINT_FILE */
# ifdef LBER_OPT_DEBUG_LEVEL
      if (cfg->ldc_debug != 0)
	{
	  ber_set_option (NULL, LBER_OPT_DEBUG_LEVEL, &cfg->ldc_debug);
	  ldap_set_option (NULL, LDAP_OPT_DEBUG_LEVEL, &cfg->ldc_debug);
	}
# endif	/* LBER_OPT_DEBUG_LEVEL */
    }
#endif /* HAVE_LDAP_SET_OPTION */

#ifdef HAVE_LDAPSSL_CLIENT_INIT
  /*
   * Initialize the SSL library. 
   */
  if (cfg->ldc_ssl_on == SSL_LDAPS)
    {
      int rc = 0;
      if (__ssl_initialized == 0
	  && (rc = ldapssl_client_init (cfg->ldc_sslpath, NULL)) != LDAP_SUCCESS)
	{
          debug ("<== do_init (ldapssl_client_init failed with rc=%d)", rc);
	  return NSS_UNAVAIL;
	}
      __ssl_initialized = 1;
    }
#endif /* SSL */

  session->ls_conn = NULL;

  do_init_mechs (session);

  assert (session->ls_current_uri >= 0 && session->ls_current_uri <= NSS_LDAP_CONFIG_URI_MAX);
  assert (cfg->ldc_uris[session->ls_current_uri] != NULL);

  stat = do_init_session (session,
			  cfg->ldc_uris[session->ls_current_uri],
  			  cfg->ldc_port);
  if (stat != NSS_SUCCESS)
    {
      debug ("<== do_init (failed to initialize LDAP session)");
      return stat;
    }

  session->ls_state = LS_INITIALIZED;

  debug ("<== do_init (initialized session)");

  return NSS_SUCCESS;
}

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
static int
do_start_tls (ldap_session_t * session)
{
  int rc;
#ifdef HAVE_LDAP_START_TLS
  int msgid;
  struct timeval tv, *timeout;
  LDAPMessage *res = NULL;

  debug ("==> do_start_tls");

  rc = ldap_start_tls (session->ls_conn, NULL, NULL, &msgid);
  if (rc != LDAP_SUCCESS)
    {
      debug ("<== do_start_tls (ldap_start_tls failed: %s)", ldap_err2string (rc));
      return rc;
    }

  if (session->ls_config->ldc_bind_timelimit == LDAP_NO_LIMIT)
    {
      timeout = NULL;
    }
  else
    {
      tv.tv_sec = session->ls_config->ldc_bind_timelimit;
      tv.tv_usec = 0;
      timeout = &tv;
    }

  rc = ldap_result (session->ls_conn, msgid, 1, timeout, &res);
  if (rc > 0)
    {
      rc = ldap_result2error (session->ls_conn, res, 1);
      if (rc != LDAP_SUCCESS)
        {
          debug ("<== do_start_tls: ldap_result failed: %s)", ldap_err2string (rc));
          return rc;
        }
    }
  else 
    {
      if (rc == -1)
        {
	  if (GET_ERROR_NUMBER (session->ls_conn, &rc) != LDAP_OPT_SUCCESS)
    	    {
    	      rc = LDAP_UNAVAILABLE;
    	    }
        }
      else if (rc == 0) /* took too long */
        {
          ldap_abandon (session->ls_conn, msgid);
          rc = LDAP_TIMEOUT;
        } 

      syslog (LOG_INFO, "nss_ldap: ldap_start_tls failed: %s", ldap_err2string (rc));
      debug ("<== do_start_tls: ldap_start_tls failed: %s", ldap_err2string (rc));
      return rc;
    }

  rc = ldap_install_tls (session->ls_conn);
#else
  rc = ldap_start_tls_s (session->ls_conn, NULL, NULL);
#endif /* HAVE_LDAP_START_TLS */

  if (rc != LDAP_SUCCESS)
    {
      debug ("<== do_start_tls: start TLS failed: %s", ldap_err2string(rc));
      return rc;
    }

  debug ("<== do_start_tls");
  return LDAP_SUCCESS;
}
#endif

/*
 * Opens connection to an LDAP server - should only be called from search
 * API. Other API that just needs access to configuration and schema should
 * call do_init().
 *
 * As with do_close(), this assumes ownership of sess.
 */
static NSS_STATUS
do_open (ldap_session_t *session)
{
  ldap_config_t *cfg;
  int with_sasl;
  char *who = NULL;
  char *cred = NULL;
  NSS_STATUS stat;
  struct timeval tv;
  int timeout;
  int rc;

  debug ("==> do_open");

  assert (session->ls_conn != NULL);
  assert (session->ls_config != NULL);
  assert (session->ls_state != LS_UNINITIALIZED);

  if (session->ls_state == LS_CONNECTED_TO_DSA)
    {
      debug ("<== do_open: cached session");
      return NSS_SUCCESS;
    }

  cfg = session->ls_config;

#ifdef LDAP_OPT_THREAD_FN_PTRS
  if (_nss_ldap_ltf_thread_init (session->ls_conn) != NSS_SUCCESS)
    {
      do_close (session);
      debug ("<== do_open: thread initialization failed");
      return NSS_UNAVAIL;
    }
#endif /* LDAP_OPT_THREAD_FN_PTRS */

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (session->ls_conn, do_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (session->ls_conn, do_rebind);
#endif

  timeout = cfg->ldc_bind_timelimit * 1000;
  tv.tv_sec = cfg->ldc_bind_timelimit;
  tv.tv_usec = 0;

  SET_PROTOCOL_VERSION (session->ls_conn, &cfg->ldc_version);
  SET_DEREF (session->ls_conn, &cfg->ldc_deref);
  SET_TIMELIMIT (session->ls_conn, &cfg->ldc_timelimit);
  SET_TIMEOUT (session->ls_conn, &tv);
  SET_CONNECT_TIMEOUT (session->ls_conn, &timeout);
  SET_NETWORK_TIMEOUT (session->ls_conn, &tv);
  SET_REFERRALS (session->ls_conn, &cfg->ldc_referrals);
  SET_RESTART (session->ls_conn, &cfg->ldc_restart);

#if defined(HAVE_LDAP_START_TLS_S) || defined(HAVE_LDAP_START_TLS)
  if (cfg->ldc_ssl_on == SSL_START_TLS)
    {
      int version;

      if (GET_PROTOCOL_VERSION (session->ls_conn, &version) == LDAP_OPT_SUCCESS)
	{
	  if (version < LDAP_VERSION3)
	    {
	      version = LDAP_VERSION3;
	      SET_PROTOCOL_VERSION (session->ls_conn, &version);
	    }
	}

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
	{
	  do_close (session);
	  debug ("<== do_open: SSL setup failed");
	  return NSS_UNAVAIL;
	}

      stat = do_map_error (do_start_tls (session));
      if (stat == NSS_SUCCESS)
	{
	  debug (":== do_open: TLS startup succeeded");
	}
      else
	{
	  do_close (session);
	  debug ("<== do_open: TLS startup failed");
	  return stat;
	}
    }
  else
#endif /* HAVE_LDAP_START_TLS_S || HAVE_LDAP_START_TLS */

    /*
     * If SSL is desired, either by the "ssl" option or if this
     * is a "ldaps" URI, then enable it.
     */
  if (cfg->ldc_ssl_on == SSL_LDAPS ||
      strncasecmp (cfg->ldc_uris[session->ls_current_uri],
		   "ldaps://", sizeof ("ldaps://") - 1) == 0
     )
    {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
      int tls = LDAP_OPT_X_TLS_HARD;
      if (SET_TLS (session->ls_conn, &tls) != LDAP_OPT_SUCCESS)
	{
	  do_close (session);
	  debug ("<== do_open: TLS setup failed");
	  return NSS_UNAVAIL;
	}

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
	{
	  do_close (session);
	  debug ("<== do_open: SSL setup failed");
	  return NSS_UNAVAIL;
	}

#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
      int on = 1;
      if (ldapssl_install_routines (session->ls_conn) != LDAP_SUCCESS)
	{
	  do_close (session);
	  debug ("<== do_open: SSL setup failed");
	  return NSS_UNAVAIL;
	}
      if (SET_SSL (session->ls_conn, &on) != LDAP_OPT_SUCCESS)
	{
	  do_close (session);
	  debug ("<== do_open: SSL setup failed");
	  return NSS_UNAVAIL;
	}
#endif
    }

  /*
   * If we're running as root, let us bind as a special
   * user, so we can fake shadow passwords.
   * Thanks to Doug Nazar <nazard@dragoninc.on.ca> for this
   * patch.
   */
  if (geteuid () == 0)
    {
      who = (cfg->ldc_rootbinddn != NULL) ? cfg->ldc_rootbinddn : cfg->ldc_binddn;
      with_sasl = (cfg->ldc_rootsaslid) ? cfg->ldc_rootusesasl : cfg->ldc_usesasl;
      if (with_sasl != 0)
	{
	  cred = (cfg->ldc_rootsaslid != NULL) ? cfg->ldc_rootsaslid : cfg->ldc_saslid;
	}
      else
	{
	  cred = (cfg->ldc_rootbindpw != NULL) ? cfg->ldc_rootbindpw : cfg->ldc_bindpw;
	}
    }
  else
    {
      who = cfg->ldc_binddn;
      with_sasl = cfg->ldc_usesasl;
      if (with_sasl)
	{
	  cred = cfg->ldc_saslid;
	}
      else
	{
	  cred = cfg->ldc_bindpw;
	}
    }

  rc = do_bind (session,
		cfg->ldc_bind_timelimit,
		with_sasl ? cred : who,
		with_sasl ? NULL : cred,
		with_sasl);

  if (rc != LDAP_SUCCESS)
    {
      /* log actual LDAP error code */
      syslog (LOG_INFO,
	      "nss_ldap: failed to bind to LDAP server %s: %s",
	      cfg->ldc_uris[session->ls_current_uri],
	      ldap_err2string (rc));
      stat = do_map_error (rc);
      do_close (session);
      debug ("<== do_open: failed to bind to DSA");
    }
  else
    {
      do_set_sockopts (session);
      time (&(session->ls_timestamp));
      session->ls_state = LS_CONNECTED_TO_DSA;
      stat = NSS_SUCCESS;
      debug ("<== do_open: session connected to DSA");
    }

  return stat;
}

#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int
do_ssl_options (ldap_config_t * cfg)
{
  int rc;

  debug ("==> do_ssl_options");

  if (cfg->ldc_tls_randfile != NULL)
    {
      /* rand file */
      if ((rc = SET_TLS_RANDOM_FILE (NULL, cfg->ldc_tls_randfile)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_cacertfile != NULL)
    {
      /* ca cert file */
      if ((rc = SET_TLS_CACERTFILE (NULL, cfg->ldc_tls_cacertfile)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_cacertdir != NULL)
    {
      /* ca cert directory */
      if ((rc = SET_TLS_CACERTDIR (NULL, cfg->ldc_tls_cacertdir)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTDIR failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  /* require cert? */
  if (cfg->ldc_tls_checkpeer > -1)
    {
      if ((rc = SET_TLS_REQUIRE_CERT (NULL, &cfg->ldc_tls_checkpeer)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_ciphers != NULL)
    {
      /* set cipher suite */
      if ((rc = SET_TLS_CIPHER_SUITE (NULL, cfg->ldc_tls_ciphers)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_cert != NULL)
    {
      /* set certificate */
      if ((rc = SET_TLS_CERTFILE (NULL, cfg->ldc_tls_cert)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CERTFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_key != NULL)
    {
      /* set private key */
      if ((rc = SET_TLS_KEYFILE (NULL, cfg->ldc_tls_key)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_KEYFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  debug ("<== do_ssl_options");

  return LDAP_SUCCESS;
}
#endif

static int
do_sasl_interactive_bind (ldap_session_t *session, int timelimit, const char *dn, const char *pw)
{
  int rc = -1;

  debug ("==> do_sasl_interactive_bind: timelimit=%d, dn =%s, pw =%s", timelimit, dn, pw);

#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)
  if (session->ls_config->ldc_sasl_secprops != NULL)
    {
      if ((rc = SET_SASL_SECPROPS (session->ls_conn, session->ls_config->ldc_sasl_secprops)) != LDAP_OPT_SUCCESS)
	{
	  debug ("<== do_sasl_interactive_bind: unable to set SASL security properties");
	  return rc;
	}
    }

  /*
   * The timelimit option passed in here has no effect. We assume that the timeout option
   * has already been set on the connection. If not then this will hang until the
   * default timeouts occur if the connection cannot be made
   */
  rc = ldap_sasl_interactive_bind_s (session->ls_conn, dn, "GSSAPI", NULL, NULL,
				     LDAP_SASL_QUIET,
				     do_sasl_interact, (void *) pw);
#endif

  debug("<== do_sasl_interactive_bind returns %s", ldap_err2string(rc));

  return rc;
}

static int
do_sasl_bind (ldap_session_t *session, int timelimit, const char *dn, const char *pw)
{
  int rc = -1;
  int mech_rc = -1;
  ldap_session_mech_t selectedMech = NULL;

  debug ("==> do_sasl_bind: timelimit=%d, dn =%s, pw =%s", timelimit, dn, pw);

#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)

# if defined(HAVE_LDAP_GSS_BIND)
  return ldap_gss_bind (session->ls_conn, dn, pw, GSSSASL_NO_SECURITY_LAYER, LDAP_SASL_GSSAPI);
# else
  if (session->ls_mechs != NULL)
    {
      int i;

      for (i = 0; i < session->ls_mechs->lsms_count; i++)
	{
	  mech_rc = session->ls_mechs->lsms_mechs[i]->lsm_select (session);
	  if (mech_rc == 0)
	    {
	      selectedMech = session->ls_mechs->lsms_mechs[i];
	      break;
	    }
	}

      if (selectedMech == NULL)
	{
	  /* All mechs failed */
	  debug ("<== do_sasl_bind: failed to select any SASL mechanism - %s",
		 ldap_err2string(mech_rc));

	  return mech_rc;
	}
    }

  rc = do_sasl_interactive_bind (session, timelimit, dn, pw);

  if (selectedMech != NULL)
    {
      mech_rc = selectedMech->lsm_restore (session);
      if (mech_rc != 0)
	{
	  /* All mechs failed */
	  debug ("<== do_sasl_bind: failed to restore any SASL mechanism - %s",
		 ldap_err2string(mech_rc));
	  return mech_rc;
	}
    }
# endif
#endif

  debug ("<== do_sasl_bind returns %s", ldap_err2string(rc));

  return rc;
}

static int
do_bind (ldap_session_t *session, int timelimit, const char *dn, const char *pw, int with_sasl)
{
  int rc;
  int msgid;
  struct timeval tv;
  LDAPMessage *result;

  debug ("==> do_bind: timelimit=%d, dn=%s, pw=%s, with_sasl=%d",
	 timelimit, dn, pw, with_sasl);

  /*
   * set timelimit in ld for select() call in ldap_pvt_connect() 
   * function implemented in libldap2's os-ip.c
   */
  tv.tv_sec = timelimit;
  tv.tv_usec = 0;

  if (with_sasl != 0)
    {
      rc = do_sasl_bind (session, timelimit, dn, pw);
      debug ("<== do_bind: rc=%d", rc);
      return rc;
    }

  msgid = ldap_simple_bind (session->ls_conn, dn, pw);

  if (msgid < 0)
    {
      if (GET_ERROR_NUMBER (session->ls_conn, &rc) != LDAP_OPT_SUCCESS)
	{
	  rc = LDAP_UNAVAILABLE;
	}
      debug ("<== do_bind: rc=%d", rc);

      return rc;
    }

  rc = ldap_result (session->ls_conn, msgid, 0, &tv, &result);
  if (rc > 0)
    {
      int error = ldap_result2error (session->ls_conn, result, 1);
      debug ("<== do_bind: result=%s", ldap_err2string(rc));
      return error;
    }

  /* took too long */
  if (rc == 0)
    {
      ldap_abandon (session->ls_conn, msgid);
      rc = LDAP_TIMEOUT;
    }

  debug ("<== do_bind: result=%s", ldap_err2string(rc));

  return rc;
}

/*
 * This function initializes an enumeration context, acquiring
 * the global mutex.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
ent_context_t *
_nss_ldap_ent_context_init (ent_context_t ** pctx)
{
  ent_context_t *ctx;

  _nss_ldap_enter ();

  ctx = _nss_ldap_ent_context_init_locked (pctx);

  _nss_ldap_leave ();

  return ctx;
}

/*
 * This function initializes an enumeration context.
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
ent_context_t *
_nss_ldap_ent_context_init_locked (ent_context_t ** pctx)
{
  ent_context_t *ctx;
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_ent_context_init_locked");

  ctx = *pctx;

  if (ctx == NULL)
    {
      ctx = (ent_context_t *) calloc (1, sizeof (*ctx));
      if (ctx == NULL)
	{
	  debug ("<== _nss_ldap_ent_context_init_locked: returns NULL");
	  return NULL;
	}
      *pctx = ctx;
    }
  else
    {
      if (ctx->ec_res != NULL)
	{
	  ldap_msgfree (ctx->ec_res);
          ctx->ec_res = NULL;
	}
      if (ctx->ec_cookie != NULL)
	{
	  ber_bvfree (ctx->ec_cookie);
	}
      if (ctx->ec_msgid > -1 && do_result (session, ctx, LDAP_MSG_ONE) == NSS_SUCCESS)
	{
	  ldap_abandon (session->ls_conn, ctx->ec_msgid);
	}
    }

  ctx->ec_cookie = NULL;
  ctx->ec_res = NULL;
  ctx->ec_msgid = -1;
  ctx->ec_sd = NULL;
  ctx->ec_eof = 0;

  LS_INIT (ctx->ec_state);

  debug ("<== _nss_ldap_ent_context_init_locked returns %p", ctx);

  return ctx;
}

ent_context_t *
_nss_ldap_ent_context_init_internal_locked (ent_context_t ** pctx)
{
  ent_context_t *ctx;

  ctx = _nss_ldap_ent_context_init_locked (pctx);
  if (ctx == NULL)
    return NULL;

  ctx->ec_internal = 1;

  return ctx;
}

static void
do_context_release (ldap_session_t * session, ent_context_t * ctx, int free_context)
{
  /*
   * Abandon the search if there were more results to fetch.
   */
  if (ctx->ec_msgid > -1 && do_result (session, ctx, LDAP_MSG_ONE) == NSS_SUCCESS)
    {
      ldap_abandon (session->ls_conn, ctx->ec_msgid);
      ctx->ec_msgid = -1;
    }

  if (ctx->ec_res != NULL)
    {
      ldap_msgfree (ctx->ec_res);
      ctx->ec_res = NULL;
    }

  if (ctx->ec_cookie != NULL)
    {
      ber_bvfree (ctx->ec_cookie);
      ctx->ec_cookie = NULL;
    }

  ctx->ec_sd = NULL;
  ctx->ec_eof = 0;

  LS_INIT (ctx->ec_state);

  if (!ctx->ec_internal &&
      _nss_ldap_test_config_flag (NSS_LDAP_FLAGS_CONNECT_POLICY_ONESHOT))
    {
      do_close (session);
    }

  if (free_context)
    free (ctx);
}

/*
 * Clears a given context; we require the caller
 * to acquire the lock.
 */
void
_nss_ldap_ent_context_release (ent_context_t ** ctx)
{
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_ent_context_release");

  if (ctx == NULL || *ctx == NULL)
    {
      debug ("<== _nss_ldap_ent_context_release");
      return;
    }

  do_context_release (session, *ctx, 1);
  *ctx = NULL;

  debug ("<== _nss_ldap_ent_context_release");

  return;
}

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
/*
 * Make all triple permutations
 */
static NSS_STATUS
do_triple_permutations (const char *machine, const char *user,
			const char *domain, char *bufptr, size_t buflen)
{
  /*
   * Map a triple
   *
   *      (M,U,D)
   *
   * to the filter
   *
   *      (|(nisNetgroupTriple=P1)...(nisNetgroupTriple=PN))
   *
   * where P1..PN are all permutations of triples that may match
   * ie. including wildcards. Certainly this would be preferable
   * to do server-side with an appropriate matching rule.
   */
  char escaped_machine[3 * (MAXHOSTNAMELEN + 1)];
  char escaped_user[3 * (LOGNAME_MAX + 1)];
  char escaped_domain[3 * (MAXHOSTNAMELEN + 1)];
  const char *AT_NISNETGROUPTRIPLE = AT (nisNetgroupTriple);
  NSS_STATUS stat;

#define ESCAPE_TRIPLE_COMPONENT(component) do { \
		if ((component) == NULL) \
		{ \
			(escaped_##component)[0] = '*'; \
			(escaped_##component)[1] = '\0'; \
		} \
		else \
		{ \
			stat = _nss_ldap_escape_string((component), (escaped_##component), \
				(sizeof((escaped_##component)))); \
			if (stat != NSS_SUCCESS) \
				return stat; \
		} \
	} while (0)

  ESCAPE_TRIPLE_COMPONENT (machine);
  ESCAPE_TRIPLE_COMPONENT (user);
  ESCAPE_TRIPLE_COMPONENT (domain);

#define _APPEND_STRING(_buffer, _buflen, _s, _len) do { \
		if ((_buflen) < (size_t)((_len) + 1)) \
		{ \
			return NSS_TRYAGAIN; \
		} \
		memcpy((_buffer), (_s), (_len)); \
		(_buffer)[(_len)] = '\0'; \
		(_buffer) += (_len); \
		(_buflen) -= (_len); \
	} while (0)

#define APPEND_STRING(_buffer, _buflen, _s) _APPEND_STRING(_buffer, _buflen, _s, strlen((_s)))
#define APPEND_CONSTANT_STRING(_buffer, _buflen, _s) _APPEND_STRING(_buffer, _buflen, _s, (sizeof((_s)) - 1))

#define APPEND_TRIPLE(_buffer, _buflen, _machine, _user, _domain) do { \
		APPEND_CONSTANT_STRING((_buffer), (_buflen), "("); \
		APPEND_STRING((_buffer), (_buflen), AT_NISNETGROUPTRIPLE); \
		APPEND_CONSTANT_STRING((_buffer), (_buflen), "=\\("); \
		if ((_machine) != NULL) \
		{ \
			APPEND_STRING((_buffer), (_buflen), (_machine)); \
		} \
		APPEND_CONSTANT_STRING((_buffer), (_buflen), ","); \
		if ((_user) != NULL) \
		{ \
			APPEND_STRING((_buffer), (_buflen), (_user)); \
		} \
		APPEND_CONSTANT_STRING((_buffer), (_buflen), ","); \
		if ((_domain) != NULL) \
		{ \
			APPEND_STRING((_buffer), (_buflen), (_domain)); \
		} \
		APPEND_CONSTANT_STRING((_buffer), (_buflen), "\\))"); \
	} while (0)

  APPEND_CONSTANT_STRING (bufptr, buflen, "(&(");
  APPEND_STRING (bufptr, buflen, AT (objectClass));
  APPEND_CONSTANT_STRING (bufptr, buflen, "=");
  APPEND_STRING (bufptr, buflen, OC (nisNetgroup));
  APPEND_CONSTANT_STRING (bufptr, buflen, ")(|");

  APPEND_TRIPLE (bufptr, buflen, escaped_machine, escaped_user,
		 escaped_domain);
  APPEND_TRIPLE (bufptr, buflen, escaped_machine, escaped_user, NULL);
  APPEND_TRIPLE (bufptr, buflen, escaped_machine, NULL, NULL);
  APPEND_TRIPLE (bufptr, buflen, NULL, escaped_user, escaped_domain);
  APPEND_TRIPLE (bufptr, buflen, NULL, escaped_user, NULL);
  APPEND_TRIPLE (bufptr, buflen, escaped_machine, NULL, escaped_domain);
  APPEND_TRIPLE (bufptr, buflen, NULL, NULL, escaped_domain);
  APPEND_TRIPLE (bufptr, buflen, NULL, NULL, NULL);

  APPEND_CONSTANT_STRING (bufptr, buflen, "))");

  return NSS_SUCCESS;
}
#endif /* HAVE_NSSWITCH_H || HAVE_IRS_H */

/*
 * AND or OR a set of filters.
 */
static NSS_STATUS
do_aggregate_filter (const char **values,
		     ldap_args_types_t type,
		     const char *filterprot, char *bufptr, size_t buflen)
{
  NSS_STATUS stat;
  const char **valueP;

  assert (buflen > sizeof ("(|)"));

  bufptr[0] = '(';
  bufptr[1] = (type == LA_TYPE_STRING_LIST_AND) ? '&' : '|';

  bufptr += 2;
  buflen -= 2;

  for (valueP = values; *valueP != NULL; valueP++)
    {
      size_t len;
      char filter[LDAP_FILT_MAXSIZ], escapedBuf[LDAP_FILT_MAXSIZ];

      stat =
	_nss_ldap_escape_string (*valueP, escapedBuf, sizeof (escapedBuf));
      if (stat != NSS_SUCCESS)
	return stat;

      snprintf (filter, sizeof (filter), filterprot, escapedBuf);
      len = strlen (filter);

      if (buflen < len + 1 /* ')' */ )
	return NSS_TRYAGAIN;

      memcpy (bufptr, filter, len);
      bufptr[len] = '\0';
      bufptr += len;
      buflen -= len;
    }

  if (buflen < 2)
    return NSS_TRYAGAIN;

  *bufptr++ = ')';
  *bufptr++ = '\0';

  buflen -= 2;

  return NSS_SUCCESS;
}

/*
 * Do the necessary formatting to create a string filter.
 */
static NSS_STATUS
do_filter (const ldap_args_t * args, const char *filterprot,
	   ldap_service_search_descriptor_t * sd, char *userBuf,
	   size_t userBufSiz, char **dynamicUserBuf, const char **retFilter)
{
  char buf1[LDAP_FILT_MAXSIZ], buf2[LDAP_FILT_MAXSIZ];
  char *filterBufP, filterBuf[LDAP_FILT_MAXSIZ];
  size_t filterSiz;
  NSS_STATUS stat = NSS_SUCCESS;

  debug ("==> do_filter");

  *dynamicUserBuf = NULL;

  if (args != NULL && args->la_type != LA_TYPE_NONE)
    {
      /* choose what to use for temporary storage */

      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  filterBufP = filterBuf;
	  filterSiz = sizeof (filterBuf);
	}
      else
	{
	  filterBufP = userBuf;
	  filterSiz = userBufSiz;
	}

      switch (args->la_type)
	{
	case LA_TYPE_STRING:
	  stat = _nss_ldap_escape_string (args->la_arg1.la_string, buf1,
					  sizeof (buf1));
	  if (stat != NSS_SUCCESS)
	    break;

	  snprintf (filterBufP, filterSiz, filterprot, buf1);
	  break;
	case LA_TYPE_NUMBER:
	  snprintf (filterBufP, filterSiz, filterprot,
		    args->la_arg1.la_number);
	  break;
	case LA_TYPE_STRING_AND_STRING:
	  stat = _nss_ldap_escape_string (args->la_arg1.la_string, buf1,
					  sizeof (buf1));
	  if (stat != NSS_SUCCESS)
	    break;

	  stat = _nss_ldap_escape_string (args->la_arg2.la_string, buf2,
					  sizeof (buf2));
	  if (stat != NSS_SUCCESS)
	    break;

	  snprintf (filterBufP, filterSiz, filterprot, buf1, buf2);
	  break;
	case LA_TYPE_NUMBER_AND_STRING:
	  stat = _nss_ldap_escape_string (args->la_arg2.la_string, buf1,
					  sizeof (buf1));
	  if (stat != NSS_SUCCESS)
	    break;

	  snprintf (filterBufP, filterSiz, filterprot,
		    args->la_arg1.la_number, buf1);
	  break;
#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
	case LA_TYPE_TRIPLE:
	  do
	    {
	      stat = do_triple_permutations (args->la_arg1.la_triple.host,
					     args->la_arg1.la_triple.user,
					     args->la_arg1.la_triple.domain,
					     filterBufP, filterSiz);
	      if (stat == NSS_TRYAGAIN)
		{
		  filterBufP = *dynamicUserBuf = realloc (*dynamicUserBuf,
							  2 * filterSiz);
		  if (filterBufP == NULL)
		    return NSS_UNAVAIL;
		  filterSiz *= 2;
		}
	    }
	  while (stat == NSS_TRYAGAIN);
	  break;
#endif /* HAVE_NSSWITCH_H || HAVE_IRS_H */
	case LA_TYPE_STRING_LIST_OR:
	case LA_TYPE_STRING_LIST_AND:
	  do
	    {
	      stat = do_aggregate_filter (args->la_arg1.la_string_list,
					  args->la_type,
					  filterprot, filterBufP, filterSiz);
	      if (stat == NSS_TRYAGAIN)
		{
		  filterBufP = *dynamicUserBuf = realloc (*dynamicUserBuf,
							  2 * filterSiz);
		  if (filterBufP == NULL)
		    return NSS_UNAVAIL;
		  filterSiz *= 2;
		}
	    }
	  while (stat == NSS_TRYAGAIN);
	  break;
	default:
	  return NSS_UNAVAIL;
	  break;
	}

      if (stat != NSS_SUCCESS)
	return stat;

      /*
       * This code really needs to be cleaned up.
       */
      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  size_t filterBufPLen = strlen (filterBufP);

	  /* remove trailing bracket */
	  if (filterBufP[filterBufPLen - 1] == ')')
	    filterBufP[filterBufPLen - 1] = '\0';

	  if (*dynamicUserBuf != NULL)
	    {
	      char *oldDynamicUserBuf = *dynamicUserBuf;
	      size_t dynamicUserBufSiz;

	      dynamicUserBufSiz = filterBufPLen + strlen (sd->lsd_filter) + sizeof ("())");
	      *dynamicUserBuf = malloc (dynamicUserBufSiz);
	      if (*dynamicUserBuf == NULL)
		{
		  free (oldDynamicUserBuf);
		  return NSS_UNAVAIL;
		}

	      snprintf (*dynamicUserBuf, dynamicUserBufSiz, "%s(%s))",
			filterBufP, sd->lsd_filter);
	      free (oldDynamicUserBuf);
	    }
	  else
	    {
	      snprintf (userBuf, userBufSiz, "%s(%s))",
			filterBufP, sd->lsd_filter);
	    }
	}

      if (*dynamicUserBuf != NULL)
	*retFilter = *dynamicUserBuf;
      else
	*retFilter = userBuf;
    }
  else
    {
      /* no arguments, probably an enumeration filter */
      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  snprintf (userBuf, userBufSiz, "(&%s(%s))",
		    filterprot, sd->lsd_filter);
	  *retFilter = userBuf;
	}
      else
	{
	  *retFilter = filterprot;
	}
    }

  debug ("<== do_filter: %s", *retFilter);

  return NSS_SUCCESS;
}

/*
 * Wrapper around ldap_result() to skip over search references
 * and deal transparently with the last entry.
 */
static NSS_STATUS
do_result (ldap_session_t *session, ent_context_t * ctx, int all)
{
  int rc = LDAP_UNAVAILABLE;
  NSS_STATUS stat = NSS_TRYAGAIN;
  struct timeval tv, *tvp;

  debug ("==> do_result");

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      debug ("<== do_result: session not connected");
      return NSS_UNAVAIL;
    }

  do
    {
      if (ctx->ec_res != NULL)
	{
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	}

      if (session->ls_config->ldc_timelimit == LDAP_NO_LIMIT)
	{
	  tvp = NULL;
	}
      else
	{
	  tv.tv_sec = session->ls_config->ldc_timelimit;
	  tv.tv_usec = 0;
	  tvp = &tv;
	}

      debug(":== do_result: call ldap_result");

      rc =
	ldap_result (session->ls_conn, ctx->ec_msgid, all, tvp,
		     &ctx->ec_res);

      debug (":== do_result: ldap_result returns %X(%d)", rc, rc);

      switch (rc)
	{
	case -1:
	  if (GET_ERROR_NUMBER (session->ls_conn, &rc) != LDAP_OPT_SUCCESS)
	    {
	      debug (":== do_result: ldap_result error %s(%d)", ldap_err2string (rc), rc);
	      rc = LDAP_UNAVAILABLE;
	    }
	  syslog (LOG_ERR, "nss_ldap: could not get LDAP result - %s", ldap_err2string (rc));
	  debug (":== do_result: could not get LDAP result %s(%d)", ldap_err2string (rc), rc);
	  stat = NSS_UNAVAIL;
	  break;
	case 0:
	  syslog (LOG_ERR, "nss_ldap: count not get LDAP result - request timed out");
	  debug (":== do_result: could not get LDAP result - request timed out");
	  rc = LDAP_TIMEOUT;
	  stat = NSS_UNAVAIL;
	  break;
	case LDAP_RES_SEARCH_ENTRY:
	  stat = NSS_SUCCESS;
	  break;
	case LDAP_RES_SEARCH_RESULT:
	  if (all == LDAP_MSG_ALL)
	    {
	      /* we asked for the result chain, we got it. */
	      stat = NSS_SUCCESS;
	    }
	  else
	    {
#ifdef LDAP_MORE_RESULTS_TO_RETURN
	      int parserc;
	      /* NB: this frees ctx->ec_res */
	      LDAPControl **resultControls = NULL;

	      if (ctx->ec_cookie != NULL)
		{
		  ber_bvfree(ctx->ec_cookie);
		  ctx->ec_cookie = NULL;
		}

	      debug (":== do_result: call ldap_parse_result");
	      parserc =
		ldap_parse_result (session->ls_conn, ctx->ec_res, &rc, NULL,
				   NULL, NULL, &resultControls, 1);
	      if (parserc != LDAP_SUCCESS
		  && parserc != LDAP_MORE_RESULTS_TO_RETURN)
		{
		  ldap_abandon (session->ls_conn, ctx->ec_msgid);
		  syslog (LOG_ERR,
			  "nss_ldap: could not get LDAP result - %s",
			  ldap_err2string (parserc));
		  stat = NSS_UNAVAIL;
		}
	      else if (resultControls != NULL)
		{
		  /* See if there are any more pages to come */
		  debug (":== do_result: call ldap_parse_page_control");
		  /* Bug in LDAP library do not reset errno */
		  {
		    int erc;
		    GET_ERROR_NUMBER (session->ls_conn, &erc);
		    debug(":== do_result: error prior to call to ldap_parse_page_control %s(%d)", ldap_err2string (erc), erc);
		    erc = LDAP_SUCCESS;
		    SET_ERROR_NUMBER (session->ls_conn, &erc);
		  }
		  parserc = ldap_parse_page_control (session->ls_conn,
						     resultControls, NULL,
						     &(ctx->ec_cookie));
		  ldap_controls_free (resultControls);
		  stat = NSS_NOTFOUND;
		}
	      else
		{
		  stat = NSS_NOTFOUND;
		}
#else
	      stat = NSS_NOTFOUND;
#endif /* LDAP_MORE_RESULTS_TO_RETURN */
	      ctx->ec_res = NULL;
	      ctx->ec_msgid = -1;
	    }
	  break;
	default:
	  stat = NSS_UNAVAIL;
	  break;
	}
    }
#ifdef LDAP_RES_SEARCH_REFERENCE
  while (rc == LDAP_RES_SEARCH_REFERENCE);
#else
  while (0);
#endif /* LDAP_RES_SEARCH_REFERENCE */

  if (stat == NSS_SUCCESS)
    time (&session->ls_timestamp);

  debug ("<== do_result: returns %s(%d), ldap result %s",
	 __nss_ldap_status2string(stat), stat, ldap_err2string(rc));

  return stat;
}

static void
do_sleep (long usecs)
{
  /*
   * Historically nss_ldap did not attempt to resume sleep in the
   * event of a signal. This is probably useful behaviour (so that
   * a user can interrupt) so it is preserved here.
   */
#if defined(HAVE_NANOSLEEP)
  struct timespec ts;

  ts.tv_sec = usecs / USECSPERSEC;
  ts.tv_nsec = (usecs % USECSPERSEC) * 1000;
#elif defined(HAVE_USLEEP)
  usleep(usecs);
#else
  struct timeval tv;

  tv.tv_sec = usecs / USECSPERSEC;
  tv.tv_usec = usecs % USECSPERSEC;

  select(0, NULL, NULL, NULL, &tv);
#endif
}

/*
 * Function to call either do_search() or do_search_s() with
 * reconnection logic.
 */
static NSS_STATUS
do_with_reconnect (ldap_session_t *session, const char *base, int scope,
		   const char *filter, const char **attrs, int sizelimit,
		   void *private, search_func_t search_func)
{
  int rc = LDAP_UNAVAILABLE, tries = 0, backoff = 0;
  int start_uri = 0, log = 0;
  NSS_STATUS stat = NSS_UNAVAIL;
  int maxtries;
  int hard;
  int firstTime = 1;

  debug ("==> do_with_reconnect");

  /* caller must successfully call do_init() first */
  assert (session->ls_config != NULL);

  hard = (session->ls_config->ldc_reconnect_pol != LP_RECONNECT_SOFT);

  maxtries = session->ls_config->ldc_reconnect_maxconntries +
	     session->ls_config->ldc_reconnect_tries;

  while (1)
    {
      /* For each "try", attempt to connect to all specified URIs */
      start_uri = session->ls_current_uri;
      while (1)
	{
	  debug (":== do_with_reconnect: check if connection is initialized");

	  stat = do_check_init (session);

	  if (stat == NSS_SUCCESS && session->ls_state == LS_CONNECTED_TO_DSA)
	    {
	      debug (":== do_with_reconnect: trying to search %s, with base %s, scope %d and filter %s",
		     session->ls_config->ldc_uris[session->ls_current_uri],
		     base ? base : "NULL", scope, filter ? filter : "NULL");

	      rc = search_func (session, base, scope, filter, attrs, sizelimit, private);

	      debug (":== do_with_reconnect: search of %s returned %s",
		     session->ls_config->ldc_uris[session->ls_current_uri],
		     ldap_err2string(rc));

	      stat = do_map_error (rc);

	      debug (":== do_with_reconnect: search result from %s maps to %s(%d)",
		     session->ls_config->ldc_uris[session->ls_current_uri],
		     __nss_ldap_status2string(stat), stat);

	      if (stat != NSS_UNAVAIL && stat != NSS_TRYAGAIN)
		{
		  goto got_result;
		}
	    }

	  while (stat != NSS_SUCCESS || session->ls_state != LS_CONNECTED_TO_DSA)
	    {
	      if (firstTime == 0)
		{
		  debug (":== do_with_reconnect: Trying next URI");

		  session->ls_current_uri++;

		  /* Wrap round to the front of the list */
		  if (session->ls_config->ldc_uris[session->ls_current_uri] == NULL)
		    session->ls_current_uri = 0;

		  if (session->ls_current_uri == start_uri)
		    goto tried_all_uris;

		  log++;
		}
	      else
		{
		  /* First time round try to reconnect to the current uri */
		  firstTime = 0; /* Note we have done the first one */
		}

	      if (session->ls_state != LS_INITIALIZED)
		{
		  debug (":== do_with_reconnect: session not initialized - initialize it");

		  stat = do_init (session);

		  debug (":== do_with_reconnect: do_init returns %s(%d)", __nss_ldap_status2string(stat), stat);
 
		  if (stat != NSS_SUCCESS)
		    continue;
		}

	      assert (session->ls_config->ldc_uris[session->ls_current_uri] != NULL);

	      debug (":== do_with_reconnect: trying to open %s",
		     session->ls_config->ldc_uris[session->ls_current_uri]);

	      stat = do_open (session);

	      debug (":== do_with_reconnect: open of %s returned %s(%d)",
		     session->ls_config->ldc_uris[session->ls_current_uri],
		     __nss_ldap_status2string(stat), stat);
	    }
	}

  tried_all_uris:
      /* Will exit the above loop if:
       * 1. Search succeeded - stat = NSS_SUCCESS
       * 2. Failed to initialise a connection to any of the URIs
       * 3. Failed to open a connection to any of the URIs
      */

      /* Release all of the session resources */
      do_close (session);

      /*
       * If a soft reconnect policy is specified, then do not
       * try to reconnect to the LDAP server if it is down.
       */
      if (session->ls_config->ldc_reconnect_pol == LP_RECONNECT_SOFT)
	{
	  break;
	}

      ++tries;

      if (tries >= maxtries)
	{
	  break;
	}

      if (tries >= session->ls_config->ldc_reconnect_maxconntries)
	{
	  if (backoff == 0)
	    backoff = session->ls_config->ldc_reconnect_sleeptime;
	  else if (backoff * 2 < session->ls_config->ldc_reconnect_maxsleeptime)
	    backoff *= 2;

	  syslog (LOG_INFO,
		  "nss_ldap: reconnecting to LDAP server (sleeping %d.%06d seconds)...",
		  backoff / USECSPERSEC, backoff % USECSPERSEC);
	  do_sleep (backoff);
	}
      else if (tries > 1)
	{
	  /* Don't sleep, reconnect immediately. */
	  syslog (LOG_INFO, "nss_ldap: reconnecting to LDAP server...");
	}
    }

 got_result:
  switch (stat)
    {
    case NSS_UNAVAIL:
      syslog (LOG_ERR, "nss_ldap: could not search LDAP server - %s",
	      ldap_err2string (rc));
      break;
    case NSS_TRYAGAIN:
      syslog (LOG_ERR,
	      "nss_ldap: could not %s %sconnect to LDAP server - %s",
	      hard ? "hard" : "soft", tries ? "re" : "",
	      ldap_err2string (rc));
      stat = NSS_UNAVAIL;
      break;
    case NSS_SUCCESS:
      if (log != 0)
	{
	  char *uri = session->ls_config->ldc_uris[session->ls_current_uri];

	  if (uri == NULL)
	    uri = "(null)";

	  if (tries > 0)
	    syslog (LOG_INFO,
	      "nss_ldap: reconnected to LDAP server %s after %d attempt%s",
	      uri, tries, (tries == 1) ? "" : "s");
	  else
	    syslog (LOG_INFO, "nss_ldap: reconnected to LDAP server %s", uri);
	}
      time (&session->ls_timestamp);
      break;
    case NSS_NOTFOUND:
      break;
    default:
      syslog (LOG_ERR,
	      "nss_ldap: could not search LDAP server: %s(%d), LDAP error code %s(%d)",
	      __nss_ldap_status2string(stat), stat, ldap_err2string(rc), rc);
      debug (":== do_with_reconnect: could not search LDAP server: %s(%d), LDAP error code %s(%d)",
	      __nss_ldap_status2string(stat), stat, ldap_err2string(rc), rc);
      break;
    }

  debug ("<== do_with_reconnect returns %s(%d)", __nss_ldap_status2string(stat), stat);

  assert (stat != NSS_TRYAGAIN);

  return stat;
}

/*
 * Synchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search_s().
 */
static int
do_search_s (ldap_session_t *session, const char *base, int scope,
	     const char *filter, const char **attrs, int sizelimit,
	     LDAPMessage ** res)
{
  int rc;
  struct timeval tv, *tvp;

  debug ("==> do_search_s");

  SET_SIZELIMIT (session->ls_conn, &sizelimit);

  if (session->ls_config->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = session->ls_config->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  debug (":== do_search_s: call ldap_search_st");
  rc = ldap_search_st (session->ls_conn, base, scope, filter,
		       (char **) attrs, 0, tvp, res);

  debug ("<== do_search_s: ldap_search_st returns %s(%d)", ldap_err2string(rc), rc);

  return rc;
}

/*
 * Asynchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search().
 */
static int
do_search (ldap_session_t *session, const char *base, int scope,
	   const char *filter, const char **attrs, int sizelimit, int *msgid)
{
  int rc;
  LDAPControl *serverCtrls[2] = { NULL, NULL };
  LDAPControl **pServerCtrls;

  debug ("==> do_search");

#ifdef HAVE_LDAP_SEARCH_EXT
  if (_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_PAGED_RESULTS))
    {
      debug (":== do_search: call ldap_create_page_control");
      /* Bug in ldap library does not clear errno */
      {
	int erc;

	GET_ERROR_NUMBER (session->ls_conn, &erc);
	debug (":== do_search: error number prior to call to ldap_create_page_control %d", erc);
	erc = LDAP_SUCCESS;
	SET_ERROR_NUMBER (session->ls_conn, &erc);
      }
      rc = ldap_create_page_control (session->ls_conn,
				     session->ls_config->ldc_pagesize,
				     NULL, 0, &serverCtrls[0]);
      debug (":== do_search: ldap_create_page_control returns %s(%d)",
	     ldap_err2string(rc), rc);
      if (rc != LDAP_SUCCESS)
	{
	  debug ("<== do_search: returns %d", rc);
	  return rc;
	}

      pServerCtrls = serverCtrls;
    }
  else
    {
      pServerCtrls = NULL;
    }

  debug (":== do_search: call ldap_search_ext");
  rc = ldap_search_ext (session->ls_conn, base, scope, filter,
			(char **) attrs, 0, pServerCtrls, NULL,
			LDAP_NO_LIMIT, sizelimit, msgid);
  debug (":== do_search: ldap_search_ext returns %s(%d)",
	 ldap_err2string(rc), rc);
  if (pServerCtrls != NULL)
    {
      ldap_control_free (serverCtrls[0]);
      serverCtrls[0] = NULL;
    }

#else
  SET_SIZELIMIT (session->ls_conn, &sizelimit);

  debug (":== do_search: call ldap_search");
  *msgid = ldap_search (session->ls_conn, base, scope, filter,
			(char **) attrs, 0);
  debug (":== do_search: ldap_search returned %d", *msgid);
  if (*msgid < 0)
    {
      if (GET_ERROR_NUMBER (session->ls_conn, &rc) != LDAP_OPT_SUCCESS)
	{
	  debug (":== do_search: failed to get error number from ldap_search");
	  rc = LDAP_UNAVAILABLE;
	}
      debug (":== do_search: error from ldap_search is %s(%d)",
	     ldap_err2string(rc), rc);
    }
  else
    {
      rc = LDAP_SUCCESS;
    }
#endif /* HAVE_LDAP_SEARCH_EXT */

  debug ("<== do_search");

  return rc;
}

static void
do_map_errno (NSS_STATUS status, int *errnop)
{
  if (status == NSS_TRYAGAIN)
    {
#ifdef HAVE_NSSWITCH_H
      errno = ERANGE;
      *errnop = 1; /* this is really erange */
#else
      *errnop = errno = ERANGE;
#endif
    }
  else
    {
      *errnop = 0;
    }
}

/*
 * Tries parser function "parser" on entries, calling do_result()
 * to retrieve them from the LDAP server until one parses
 * correctly or there is an exceptional condition.
 */
static NSS_STATUS
do_parse (ldap_session_t *session, ent_context_t * ctx, void *result, char
	  *buffer, size_t buflen, int *errnop, parser_t parser)
{
  NSS_STATUS parseStat = NSS_NOTFOUND;

  debug ("==> do_parse");

  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
    {
      NSS_STATUS resultStat = NSS_SUCCESS;

      if (ctx->ec_state.ls_retry == 0 &&
	  (ctx->ec_state.ls_type == LS_TYPE_KEY
	   || ctx->ec_state.ls_info.ls_index == -1))
	{
	  resultStat = do_result (session, ctx, LDAP_MSG_ONE);
	}

      if (resultStat != NSS_SUCCESS)
	{
	  /* Could not get a result; bail */
	  parseStat = resultStat;
	  break;
	}

      /*
       * We have an entry; now, try to parse it.
       *
       * If we do not parse the entry because of a schema
       * violation, the parser should return NSS_NOTFOUND.
       * We'll keep on trying subsequent entries until we
       * find one which is parseable, or exhaust available
       * entries, whichever is first.
       */
      parseStat = parser (ctx->ec_res, &ctx->ec_state, result,
			  buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_TRYAGAIN && buffer != NULL ? 1 : 0);

      /* free entry is we're moving on */
      if (ctx->ec_state.ls_retry == 0 &&
	  (ctx->ec_state.ls_type == LS_TYPE_KEY
	   || ctx->ec_state.ls_info.ls_index == -1))
	{
	  /* we don't need the result anymore, ditch it. */
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	}
    }
  while (parseStat == NSS_NOTFOUND);

  do_map_errno (parseStat, errnop);

  debug ("<== do_parse");

  return parseStat;
}

/*
 * Parse, fetching results from chain instead of server.
 */
static NSS_STATUS
do_parse_s (ldap_session_t * session, ent_context_t * ctx,
	    void *result, char *buffer, size_t buflen,
	    int *errnop, parser_t parser)
{
  NSS_STATUS parseStat = NSS_NOTFOUND;
  LDAPMessage *e = NULL;

  debug ("==> do_parse_s");

  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  do
    {
      if (ctx->ec_state.ls_retry == 0 &&
	  (ctx->ec_state.ls_type == LS_TYPE_KEY
	   || ctx->ec_state.ls_info.ls_index == -1))
	{
	  if (e == NULL)
	    e = ldap_first_entry (session->ls_conn, ctx->ec_res);
	  else
	    e = ldap_next_entry (session->ls_conn, e);
	}

      if (e == NULL)
	{
	  /* Could not get a result; bail */
	  parseStat = NSS_NOTFOUND;
	  break;
	}

      /*
       * We have an entry; now, try to parse it. 
       *
       * If we do not parse the entry because of a schema
       * violation, the parser should return NSS_NOTFOUND.
       * We'll keep on trying subsequent entries until we
       * find one which is parseable, or exhaust available
       * entries, whichever is first.
       */
      parseStat = parser (e, &ctx->ec_state, result, buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_TRYAGAIN && buffer != NULL ? 1 : 0);
    }
  while (parseStat == NSS_NOTFOUND);

  do_map_errno (parseStat, errnop);

  debug ("<== do_parse_s");

  return parseStat;
}

/*
 * Read an entry from the directory, a la X.500. This is used
 * for functions that need to retrieve attributes from a DN,
 * such as the RFC2307bis group expansion function.
 */
NSS_STATUS
_nss_ldap_read (const char *dn, const char **attributes, LDAPMessage ** res)
{
  ldap_session_t *session = &__session;

  return do_with_reconnect (session, dn, LDAP_SCOPE_BASE, "(objectclass=*)",
			    attributes, 1, /* sizelimit */ res,
			    (search_func_t) do_search_s);
}

/*
 * Simple wrapper around ldap_get_values(). Requires that
 * session is already established.
 */
char **
_nss_ldap_get_values (LDAPMessage * e, const char *attr)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_get_values (session->ls_conn, e, (char *) attr);
}

/*
 * Simple wrapper around ldap_get_dn(). Requires that
 * session is already established.
 */
char *
_nss_ldap_get_dn (LDAPMessage * e)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_get_dn (session->ls_conn, e);
}

/*
 * Simple wrapper around ldap_first_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_first_entry (LDAPMessage * res)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_first_entry (session->ls_conn, res);
}

/*
 * Simple wrapper around ldap_next_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_next_entry (LDAPMessage * res)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_next_entry (session->ls_conn, res);
}

char *
_nss_ldap_first_attribute (LDAPMessage * entry, BerElement ** berptr)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_first_attribute (session->ls_conn, entry, berptr);
}

char *
_nss_ldap_next_attribute (LDAPMessage * entry, BerElement * ber)
{
  ldap_session_t *session = &__session;

  if (session->ls_state != LS_CONNECTED_TO_DSA)
    {
      return NULL;
    }
  assert (session->ls_conn != NULL);

  return ldap_next_attribute (session->ls_conn, entry, ber);
}

static void
do_search_params (const ldap_session_t *session,
		  const ldap_service_search_descriptor_t *sd,
		  char *sdBase,
		  size_t sdBaseSize,
		  const char **base,
		  int *scope)
{
  debug ("==> do_search_params");

  if (sd != NULL)
    {
      size_t len = strlen (sd->lsd_base);

      if (sd->lsd_base[len - 1] == ',')
	{
	  /* is relative */
	  snprintf (sdBase, sdBaseSize, "%s%s", sd->lsd_base, session->ls_config->ldc_base);
	  *base = sdBase;
	}
      else
	{
	  *base = sd->lsd_base;
	}

      if (sd->lsd_scope != -1)
	{
	  *scope = sd->lsd_scope;
	}
    }

  debug ("<== do_search_params base=%s, scope=%d", *base, *scope);
}

static NSS_STATUS
do_filter_with_reconnect(ldap_session_t *session,
			 const ldap_args_t *args,
			 const char *filterprot,
			 ldap_service_search_descriptor_t *sd,
			 const char *base, int scope,
			 const char **attrs, int sizelimit,
			 void *res, search_func_t searcher)
{
  char *dynamicFilterBuf = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ];
  const char *filter;
  NSS_STATUS stat;

  debug ("==> do_filter_with_reconnect filterprot=%s, base=%s, scope=%d, sizelimit=%d",
	 filterprot, base, scope, sizelimit);

  stat = do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf),
		    &dynamicFilterBuf, &filter);
  if (stat == NSS_SUCCESS)
    {

      stat = do_with_reconnect (session, base, scope, filter, attrs, sizelimit, res, searcher);

      if (dynamicFilterBuf != NULL)
	{
	  free (dynamicFilterBuf);
	}
    }

  debug ("<== do_filter_with_reconnect stat=%d", stat);

  return stat;
}

/*
 * The generic synchronous lookup cover function.
 * Assumes caller holds lock.
 */
NSS_STATUS
_nss_ldap_search_s (const ldap_args_t * args,
		    const char *filterprot, ldap_map_selector_t sel, const
		    char **user_attrs, int sizelimit, LDAPMessage ** res)
{
  char sdBase[LDAP_FILT_MAXSIZ];
  const char *base = NULL;
  const char **attrs;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_search_s");

  stat = do_check_init (session);

  if (stat != NSS_SUCCESS)
    {
      stat = do_init (session);
      if (stat != NSS_SUCCESS)
	{
	  debug ("<== _nss_ldap_search_s: session initialization failed");
	  return stat;
	}
    }

  /* Set some reasonable defaults. */
  base = session->ls_config->ldc_base;
  scope = session->ls_config->ldc_scope;
  attrs = NULL;

  if (args != NULL && args->la_base != NULL)
    {
      sel = LM_NONE;
      base = args->la_base;
    }

  if (sel < LM_NONE)
    {
      sd = session->ls_config->ldc_sds[sel];
    next:
      do_search_params (session, sd, sdBase, sizeof(sdBase), &base, &scope);
      attrs = session->ls_config->ldc_attrtab[sel];
    }

  stat = do_filter_with_reconnect (session, args, filterprot,
				   sd,
				   base, scope,
				   (user_attrs != NULL) ? user_attrs : attrs,
				   sizelimit,
				   (void*)res, (search_func_t)do_search_s);

  if (stat != NSS_SUCCESS)
    return stat;

  if (stat == NSS_SUCCESS &&
      ldap_count_entries (session->ls_conn, *res) == 0) /* No results */
    {
      stat = NSS_NOTFOUND;
      ldap_msgfree (*res);
      *res = NULL;
    }

  /* If no entry was returned, try the next search descriptor. */
  if (sd != NULL && sd->lsd_next != NULL)
    {
      if (stat == NSS_NOTFOUND)
	{
	  sd = sd->lsd_next;
	  goto next;
	}
    }

  debug ("<== _nss_ldap_search_s");

  return stat;
}

/*
 * The generic lookup cover function (asynchronous).
 * Assumes caller holds lock.
 */
NSS_STATUS
_nss_ldap_search (const ldap_args_t * args,
		  const char *filterprot, ldap_map_selector_t sel,
		  const char **user_attrs, int sizelimit, int *msgid,
		  ldap_service_search_descriptor_t ** csd)
{
  const char *base = NULL;
  const char **attrs;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;
  ldap_session_t *session = &__session;
  char sdBase[LDAP_FILT_MAXSIZ];

  debug ("==> _nss_ldap_search");

  *msgid = -1;

  stat = do_check_init (session);

  if (stat != NSS_SUCCESS)
    {
      stat = do_init (session);
      if (stat != NSS_SUCCESS)
	{
	  debug ("<== _nss_ldap_search: session initialization failed");
	  return stat;
	}
    }
  /* Set some reasonable defaults. */
  base = session->ls_config->ldc_base;
  scope = session->ls_config->ldc_scope;
  attrs = NULL;

  if (args != NULL && args->la_base != NULL)
    {
      sel = LM_NONE;
      base = args->la_base;
    }

  if (sel < LM_NONE || *csd != NULL)
    {
      /*
       * If we were chasing multiple descriptors and there are none left,
       * just quit with NSS_NOTFOUND.
       */
      if (*csd != NULL)
	{
	  sd = (*csd)->lsd_next;
	  if (sd == NULL)
	    return NSS_NOTFOUND;
	}
      else
	{
	  sd = session->ls_config->ldc_sds[sel];
	}

      *csd = sd;

      do_search_params (session, sd, sdBase, sizeof(sdBase), &base, &scope);

      attrs = session->ls_config->ldc_attrtab[sel];
    }

  stat = do_filter_with_reconnect (session, args, filterprot,
				   sd,
				   base, scope,
				   (user_attrs != NULL) ? user_attrs : attrs,
				   sizelimit,
				   (void*)msgid, (search_func_t)do_search);

  debug ("<== _nss_ldap_search");

  return stat;
}

#ifdef HAVE_LDAP_SEARCH_EXT
static NSS_STATUS
do_next_page (const ldap_args_t * args,
	      const char *filterprot, ldap_map_selector_t sel, int
	      sizelimit, int *msgid, struct berval *pCookie)
{
  char sdBase[LDAP_FILT_MAXSIZ];
  const char *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ], *dynamicFilterBuf = NULL;
  const char **attrs, *filter;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;
  ldap_session_t *session = &__session;
  LDAPControl *serverctrls[2] = {
    NULL, NULL
  };

  debug ("==> do_next_page");

  /* Set some reasonable defaults. */
  base = session->ls_config->ldc_base;
  scope = session->ls_config->ldc_scope;
  attrs = NULL;

  if (args != NULL && args->la_base != NULL)
    {
      sel = LM_NONE;
      base = args->la_base;
    }

  if (sel < LM_NONE)
    {
      do_search_params (session, session->ls_config->ldc_sds[sel],
			sdBase, sizeof(sdBase), &base, &scope);

      attrs = session->ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf),
	       &dynamicFilterBuf, &filter);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  debug (":== do_next_page: call ldap_create_page_control");

  {
    /* Bug in OpenLDAP library does not reset err number */
    int erc;

    GET_ERROR_NUMBER (session->ls_conn, &erc);
    debug (":== do_next_page: error number prior to call to ldap_create_page_control %d", erc);
    erc = LDAP_SUCCESS;
    SET_ERROR_NUMBER (session->ls_conn, &erc);
  }

  stat =
    ldap_create_page_control (session->ls_conn,
			      session->ls_config->ldc_pagesize,
			      pCookie, 0, &serverctrls[0]);
  debug (":== do_next_page: ldap_create_page_control returns %s(%d)",
	 ldap_err2string(stat), stat);
  if (stat != LDAP_SUCCESS)
    {
      if (dynamicFilterBuf != NULL)
	free (dynamicFilterBuf);
      return NSS_UNAVAIL;
    }

  debug (":== do_next_page: call ldap_search_ext");
  stat =
    ldap_search_ext (session->ls_conn, base,
		     session->ls_config->ldc_scope,
		     filter,
		     (char **) attrs, 0, serverctrls, NULL, LDAP_NO_LIMIT,
		     sizelimit, msgid);
  debug (":== do_next_page: ldap_search_ext returns %s(%d)",
	 ldap_err2string(stat), stat);

  ldap_control_free (serverctrls[0]);
  if (dynamicFilterBuf != NULL)
    free (dynamicFilterBuf);

  stat = (*msgid < 0) ? NSS_UNAVAIL : NSS_SUCCESS;
  debug ("<== do_next_page: returns %s(%d)",
	 __nss_ldap_status2string(stat), stat);

  return stat;
}
#endif /* HAVE_LDAP_SEARCH_EXT */

/*
 * General entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid 
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 * Locks mutex.
 */
NSS_STATUS
_nss_ldap_getent (ent_context_t ** ctx,
		  void *result, char *buffer, size_t buflen,
		  int *errnop, const char *filterprot,
		  ldap_map_selector_t sel, parser_t parser)
{
  NSS_STATUS status;

  /*
   * we need to lock here as the context may not be thread-specific
   * data (under glibc, for example). Maybe we should make the lock part
   * of the context.
   */

  debug ("==> _nss_ldap_getent");

  _nss_ldap_enter ();
  status = _nss_ldap_getent_ex (NULL, ctx, result,
				buffer, buflen,
				errnop, filterprot, sel, NULL, parser);
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_getent");

  return status;
}

/*
 * Internal entry point for enumeration routines.
 * Caller holds global mutex
 */
NSS_STATUS
_nss_ldap_getent_ex (ldap_args_t * args,
		     ent_context_t ** ctx, void *result,
		     char *buffer, size_t buflen, int *errnop,
		     const char *filterprot,
		     ldap_map_selector_t sel,
		     const char **user_attrs, parser_t parser)
{
  NSS_STATUS stat = NSS_SUCCESS;
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_getent_ex");

  if (*ctx != NULL && (*ctx)->ec_eof != 0)
    {
      debug ("<== _nss_ldap_getent_ex: EOF");
      return NSS_NOTFOUND;
    }
  else if (*ctx == NULL || (*ctx)->ec_msgid < 0)
    {
      /*
       * implicitly call setent() if this is the first time
       * or there is no active search
       */
      if (_nss_ldap_ent_context_init_locked (ctx) == NULL)
	{
	  debug ("<== _nss_ldap_getent_ex: return NSS_UNAVAIL");
	  return NSS_UNAVAIL;
	}
    }

next:
  /*
   * If ctx->ec_msgid < 0, then we haven't searched yet. Let's do it!
   */
  if ((*ctx)->ec_msgid < 0)
    {
      int msgid = 0;

      stat = _nss_ldap_search (args, filterprot, sel, user_attrs,
			       LDAP_NO_LIMIT, &msgid, &(*ctx)->ec_sd);
      if (stat != NSS_SUCCESS)
	{
	  debug ("<== _nss_ldap_getent_ex");
	  return stat;
	}

      (*ctx)->ec_msgid = msgid;
    }

  stat = do_parse (session, *ctx, result, buffer, buflen, errnop, parser);

#ifdef HAVE_LDAP_SEARCH_EXT
  if (stat == NSS_NOTFOUND)
    {
      /* Is there another page of results? */
      if ((*ctx)->ec_cookie != NULL && (*ctx)->ec_cookie->bv_len != 0)
	{
	  int msgid;

	  stat =
	    do_next_page (NULL, filterprot, sel, LDAP_NO_LIMIT, &msgid,
			  (*ctx)->ec_cookie);
	  if (stat != NSS_SUCCESS)
	    {
	      debug ("<== _nss_ldap_getent_ex");
	      return stat;
	    }
	  (*ctx)->ec_msgid = msgid;
	  stat = do_parse (session, *ctx, result, buffer, buflen, errnop, parser);
	}
    }
#endif /* HAVE_LDAP_SEARCH_EXT */

  if (stat == NSS_NOTFOUND)
    {
      if ((*ctx)->ec_sd != NULL)
	{
	  (*ctx)->ec_msgid = -1;
	  goto next;
	}
      else
	{
	  /* Mark notional end of file */
	  (*ctx)->ec_eof = 1;
	}
    }

  debug ("<== _nss_ldap_getent_ex");

  return stat;
}

/*
 * General match function.
 * Locks mutex. 
 */
NSS_STATUS
_nss_ldap_getbyname (ldap_args_t * args,
		     void *result, char *buffer, size_t buflen, int
		     *errnop, const char *filterprot,
		     ldap_map_selector_t sel, parser_t parser)
{
  NSS_STATUS stat = NSS_NOTFOUND;
  ent_context_t ctx;
  ldap_session_t *session = &__session;

  _nss_ldap_enter ();

  debug ("==> _nss_ldap_getbyname");

  memset (&ctx, 0, sizeof(ctx));
  ctx.ec_msgid = -1;

  stat = _nss_ldap_search_s (args, filterprot, sel, NULL, 1, &ctx.ec_res);
  if (stat != NSS_SUCCESS)
    {
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_getbyname");
      return stat;
    }

  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  LS_INIT (ctx.ec_state);
  ctx.ec_state.ls_type = LS_TYPE_KEY;
  ctx.ec_state.ls_info.ls_key = args->la_arg2.la_string;

  stat = do_parse_s (session, &ctx, result, buffer, buflen, errnop, parser);

  do_context_release (session, &ctx, 0);

  /* moved unlock here to avoid race condition bug #49 */
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_getbyname");

  return stat;
}

/*
 * These functions are called from within the parser, where it is assumed
 * to be safe to use the connection and the respective message.
 */

/*
 * Assign all values, bar omitvalue (if not NULL), to *valptr.
 */
NSS_STATUS
_nss_ldap_assign_attrvals (LDAPMessage * e,
			   const char *attr, const char *omitvalue,
			   char ***valptr, char **pbuffer, size_t *
			   pbuflen, size_t * pvalcount)
{
  char **vals;
  char **valiter;
  int valcount;
  char **p = NULL;
  ldap_session_t *session = &__session;

  register int buflen = *pbuflen;
  register char *buffer = *pbuffer;

  if (pvalcount != NULL)
    {
      *pvalcount = 0;
    }

  if (session->ls_conn == NULL)
    {
      return NSS_UNAVAIL;
    }

  vals = ldap_get_values (session->ls_conn, e, (char *) attr);

  valcount = (vals == NULL) ? 0 : ldap_count_values (vals);
  if (bytesleft (buffer, buflen, char *) < (valcount + 1) * sizeof (char *))
    {
      ldap_value_free (vals);
      return NSS_TRYAGAIN;
    }

  align (buffer, buflen, char *);
  p = *valptr = (char **) buffer;

  buffer += (valcount + 1) * sizeof (char *);
  buflen -= (valcount + 1) * sizeof (char *);

  if (valcount == 0)
    {
      *p = NULL;
      *pbuffer = buffer;
      *pbuflen = buflen;
      return NSS_SUCCESS;
    }

  valiter = vals;

  while (*valiter != NULL)
    {
      int vallen;
      char *elt = NULL;

      if (omitvalue != NULL && strcmp (*valiter, omitvalue) == 0)
	{
	  valcount--;
	}
      else
	{
	  vallen = strlen (*valiter);
	  if (buflen < (size_t) (vallen + 1))
	    {
	      ldap_value_free (vals);
	      return NSS_TRYAGAIN;
	    }

	  /* copy this value into the next block of buffer space */
	  elt = buffer;
	  buffer += vallen + 1;
	  buflen -= vallen + 1;

	  strncpy (elt, *valiter, vallen);
	  elt[vallen] = '\0';
	  *p = elt;
	  p++;
	}
      valiter++;
    }

  *p = NULL;
  *pbuffer = buffer;
  *pbuflen = buflen;

  if (pvalcount != NULL)
    {
      *pvalcount = valcount;
    }

  ldap_value_free (vals);
  return NSS_SUCCESS;
}

/* Assign a single value to *valptr. */
NSS_STATUS
_nss_ldap_assign_attrval (LDAPMessage * e,
			  const char *attr, char **valptr, char **buffer,
			  size_t * buflen)
{
  char **vals;
  int vallen;
  const char *ovr, *def;
  ldap_session_t *session = &__session;

  ovr = OV (attr);
  if (ovr != NULL)
    {
      vallen = strlen (ovr);
      if (*buflen < (size_t) (vallen + 1))
	{
	  return NSS_TRYAGAIN;
	}

      *valptr = *buffer;

      strncpy (*valptr, ovr, vallen);
      (*valptr)[vallen] = '\0';

      *buffer += vallen + 1;
      *buflen -= vallen + 1;

      return NSS_SUCCESS;
    }

  if (session->ls_conn == NULL)
    {
      return NSS_UNAVAIL;
    }

  vals = ldap_get_values (session->ls_conn, e, (char *) attr);
  if (vals == NULL)
    {
      def = DF (attr);
      if (def != NULL)
	{
	  vallen = strlen (def);
	  if (*buflen < (size_t) (vallen + 1))
	    {
	      return NSS_TRYAGAIN;
	    }

	  *valptr = *buffer;

	  strncpy (*valptr, def, vallen);
	  (*valptr)[vallen] = '\0';

	  *buffer += vallen + 1;
	  *buflen -= vallen + 1;

	  return NSS_SUCCESS;
	}
      else
	{
	  return NSS_NOTFOUND;
	}
    }

  vallen = strlen (*vals);
  if (*buflen < (size_t) (vallen + 1))
    {
      ldap_value_free (vals);
      return NSS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, *vals, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  ldap_value_free (vals);

  return NSS_SUCCESS;
}

const char *
_nss_ldap_locate_userpassword (LDAPMessage *e, char **vals)
{
  const char *token = NULL;
  size_t token_length = 0;
  char **valiter;
  const char *pwd = NULL;
  ldap_session_t * session = &__session;

  if (session->ls_config != NULL)
    {
      switch (session->ls_config->ldc_password_type)
	{
	case LU_RFC2307_USERPASSWORD:
	  token = "{CRYPT}";
	  token_length = sizeof ("{CRYPT}") - 1;
	  break;
	case LU_RFC3112_AUTHPASSWORD:
	  token = "CRYPT$";
	  token_length = sizeof ("CRYPT$") - 1;
	  break;
	case LU_OTHER_PASSWORD:
	  break;
	}
    }

  if (vals != NULL)
    {
      for (valiter = vals; *valiter != NULL; valiter++)
	{
	  if (token_length == 0 ||
	      strncasecmp (*valiter, token, token_length) == 0)
	    {
	      pwd = *valiter;
	      break;
	    }
	}
    }

  if (pwd == NULL)
    {
      if (_nss_ldap_oc_check (e, "shadowAccount") == NSS_SUCCESS)
	pwd = "x";
      else
	pwd = "*";
    }
  else
    pwd += token_length;

  return pwd;
}

/*
 * Assign a single value to *valptr, after examining userPassword for
 * a syntactically suitable value.
 */
NSS_STATUS
_nss_ldap_assign_userpassword (LDAPMessage * e,
			       const char *attr, char **valptr,
			       char **buffer, size_t * buflen)
{
  char **vals;
  const char *pwd;
  int vallen;
  ldap_session_t *session = &__session;


  debug ("==> _nss_ldap_assign_userpassword");

  if (session->ls_conn == NULL)
    {
      return NSS_UNAVAIL;
    }

  vals = ldap_get_values (session->ls_conn, e, (char *) attr);
  pwd = _nss_ldap_locate_userpassword (e, vals);

  vallen = strlen (pwd);

  if (*buflen < (size_t) (vallen + 1))
    {
      if (vals != NULL)
	{
	  ldap_value_free (vals);
	}
      debug ("<== _nss_ldap_assign_userpassword");
      return NSS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, pwd, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  if (vals != NULL)
    {
      ldap_value_free (vals);
    }

  debug ("<== _nss_ldap_assign_userpassword");

  return NSS_SUCCESS;
}

NSS_STATUS
_nss_ldap_oc_check (LDAPMessage * e, const char *oc)
{
  char **vals, **valiter;
  NSS_STATUS ret = NSS_NOTFOUND;
  ldap_session_t *session = &__session;

  if (session->ls_conn == NULL)
    {
      return NSS_UNAVAIL;
    }

  vals = ldap_get_values (session->ls_conn, e, AT (objectClass));
  if (vals != NULL)
    {
      for (valiter = vals; *valiter != NULL; valiter++)
	{
	  if (strcasecmp (*valiter, oc) == 0)
	    {
	      ret = NSS_SUCCESS;
	      break;
	    }
	}
    }

  if (vals != NULL)
    {
      ldap_value_free (vals);
    }

  return ret;
}

#ifdef HAVE_SHADOW_H
NSS_STATUS
_nss_ldap_shadow_date (const char *val, long default_date, long *value)
{
  int date;
  char *p;
  long long ll;
  ldap_session_t *session = &__session;

  if (val == NULL || strlen(val) == 0)
    {
      *value = default_date;
      return NSS_NOTFOUND;
    }
  ll = strtoll(val, &p, 10);
  if (p == NULL || p == val || *p != '\0')
    {
      *value = default_date;
      return NSS_NOTFOUND;
    }
  if (session->ls_config->ldc_shadow_type == LS_AD_SHADOW)
    {
      date = ll / 864000000000LL - 134774LL;
      date = (date > 99999) ? 99999 : date;
    }
  else
    {
      date = ll;
    }

  *value = date;
  return NSS_SUCCESS;
}

void
_nss_ldap_shadow_handle_flag (struct spwd *sp)
{
  ldap_session_t *session = &__session;

  if (session->ls_config->ldc_shadow_type == LS_AD_SHADOW)
    {
      if (sp->sp_flag & UF_DONT_EXPIRE_PASSWD)
	sp->sp_max = 99999;
      sp->sp_flag = 0;
    }
}
#endif /* HAVE_SHADOW_H */

const char *
_nss_ldap_map_at (ldap_map_selector_t sel, const char *attribute)
{
  const char *mapped = NULL;
  NSS_STATUS stat;
  ldap_session_t *session = &__session;

  stat = _nss_ldap_map_get (session->ls_config, sel, MAP_ATTRIBUTE, attribute, &mapped);

  return (stat == NSS_SUCCESS) ? mapped : attribute;
}

const char *
_nss_ldap_unmap_at (ldap_map_selector_t sel, const char *attribute)
{
  const char *mapped = NULL;
  NSS_STATUS stat;
  ldap_session_t *session = &__session;

  stat = _nss_ldap_map_get (session->ls_config, sel, MAP_ATTRIBUTE_REVERSE, attribute, &mapped);

  return (stat == NSS_SUCCESS) ? mapped : attribute;
}

const char *
_nss_ldap_map_oc (ldap_map_selector_t sel, const char *objectclass)
{
  const char *mapped = NULL;
  NSS_STATUS stat;
  ldap_session_t *session = &__session;

  stat = _nss_ldap_map_get (session->ls_config, sel, MAP_OBJECTCLASS, objectclass, &mapped);

  return (stat == NSS_SUCCESS) ? mapped : objectclass;
}

const char *
_nss_ldap_unmap_oc (ldap_map_selector_t sel, const char *objectclass)
{
  const char *mapped = NULL;
  NSS_STATUS stat;
  ldap_session_t *session = &__session;

  stat = _nss_ldap_map_get (session->ls_config, sel, MAP_OBJECTCLASS_REVERSE, objectclass, &mapped);

  return (stat == NSS_SUCCESS) ? mapped : objectclass;
}

const char *
_nss_ldap_map_ov (const char *attribute)
{
  const char *value = NULL;
  ldap_session_t *session = &__session;

  _nss_ldap_map_get (session->ls_config, LM_NONE, MAP_OVERRIDE, attribute, &value);

  return value;
}

const char *
_nss_ldap_map_df (const char *attribute)
{
  const char *value = NULL;
  ldap_session_t *session = &__session;

  _nss_ldap_map_get (session->ls_config, LM_NONE, MAP_DEFAULT, attribute, &value);

  return value;
}

const char *
_nss_ldap_map_mr (ldap_map_selector_t sel, const char *attribute)
{
  const char *mapped = NULL;
  NSS_STATUS stat;
  ldap_session_t *session = &__session;

  stat = _nss_ldap_map_get (session->ls_config, sel, MAP_MATCHING_RULE, attribute, &mapped);

  return (stat == NSS_SUCCESS) ? mapped : NULL;
}

NSS_STATUS
_nss_ldap_map_put (ldap_config_t * config,
		   ldap_map_selector_t sel,
		   ldap_map_type_t type,
		   const char *from,
		   const char *to)
{
  ldap_datum_t key, val;
  void **map;
  NSS_STATUS stat;

  switch (type)
    {
    case MAP_ATTRIBUTE:
      /* special handling for attribute mapping */
      if (strcmp(from, "userPassword") == 0)
	{
	  if (strcasecmp (to, "userPassword") == 0)
	    config->ldc_password_type = LU_RFC2307_USERPASSWORD;
	  else if (strcasecmp (to, "authPassword") == 0)
	    config->ldc_password_type = LU_RFC3112_AUTHPASSWORD;
	  else
	    config->ldc_password_type = LU_OTHER_PASSWORD;
	}
      else if (strcmp (from, "shadowLastChange") == 0)
	{
	  if (strcasecmp (to, "shadowLastChange") == 0)
	    config->ldc_shadow_type = LS_RFC2307_SHADOW;
	  else if (strcasecmp (to, "pwdLastSet") == 0)
	    config->ldc_shadow_type = LS_AD_SHADOW;
	  else
	    config->ldc_shadow_type = LS_OTHER_SHADOW;
	}
      break;
    case MAP_OBJECTCLASS:
    case MAP_OVERRIDE:
    case MAP_DEFAULT:
    case MAP_MATCHING_RULE:
      break;
    default:
      return NSS_NOTFOUND;
      break;
    }

  assert (sel <= LM_NONE);
  map = &config->ldc_maps[sel][type];
  assert (*map != NULL);

  NSS_LDAP_DATUM_ZERO (&key);
  key.data = (void *) from;
  key.size = strlen (from) + 1;

  NSS_LDAP_DATUM_ZERO (&val);
  val.data = (void *) to;
  val.size = strlen (to) + 1;

  stat = _nss_ldap_db_put (*map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
  if (stat == NSS_SUCCESS &&
      (type == MAP_ATTRIBUTE || type == MAP_OBJECTCLASS))
    {
      type = (type == MAP_ATTRIBUTE) ? MAP_ATTRIBUTE_REVERSE : MAP_OBJECTCLASS_REVERSE;
      map = &config->ldc_maps[sel][type];

      stat = _nss_ldap_db_put (*map, NSS_LDAP_DB_NORMALIZE_CASE, &val, &key);
    }

  return stat;
}

NSS_STATUS
_nss_ldap_map_get (ldap_config_t * config,
		   ldap_map_selector_t sel,
		   ldap_map_type_t type,
		   const char *from, const char **to)
{
  ldap_datum_t key, val;
  void *map;
  NSS_STATUS stat;

  if (config == NULL || sel > LM_NONE || type > MAP_MAX)
    {
      return NSS_NOTFOUND;
    }

  map = config->ldc_maps[sel][type];
  assert (map != NULL);

  NSS_LDAP_DATUM_ZERO (&key);
  key.data = (void *) from;
  key.size = strlen (from) + 1;

  NSS_LDAP_DATUM_ZERO (&val);

  stat = _nss_ldap_db_get (map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
  if (stat == NSS_NOTFOUND && sel != LM_NONE)
    {
      map = config->ldc_maps[LM_NONE][type];
      assert (map != NULL);
      stat = _nss_ldap_db_get (map, NSS_LDAP_DB_NORMALIZE_CASE, &key, &val);
    }

  if (stat == NSS_SUCCESS)
    *to = (char *) val.data;
  else
    *to = NULL;

  return stat;
}

/*
 * Proxy bind support for AIX. Very simple, but should do
 * the job. 
 */

#if LDAP_SET_REBIND_PROC_ARGS < 3
static ldap_proxy_bind_args_t __proxy_args = { NULL, NULL };
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_proxy_rebind (LDAP * ld, LDAP_CONST char *url, ber_tag_t request,
		 ber_int_t msgid, void *arg)
#else
static int
do_proxy_rebind (LDAP * ld, LDAP_CONST char *url, int request,
		 ber_int_t msgid)
#endif
{
  int timelimit;
  ldap_session_t *session = &__session;
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_proxy_bind_args_t *who = (ldap_proxy_bind_args_t *) arg;
#else
  ldap_proxy_bind_args_t *who = &__proxy_args;
#endif

  timelimit = session->ls_config->ldc_bind_timelimit;

  return do_bind (session, timelimit, who->binddn, who->bindpw, 0);
}
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
do_proxy_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
		 int freeit, void *arg)
#elif LDAP_SET_REBIND_PROC_ARGS == 2
static int
do_proxy_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
		 int freeit)
#endif
{
  ldap_session_t *session = &__session;
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_proxy_bind_args_t *who = (ldap_proxy_bind_args_t *) arg;
#else
  ldap_proxy_bind_args_t *who = &__proxy_args;
#endif
  if (freeit != 0)
    {
      if (*whop != NULL)
	free (*whop);
      if (*credp != NULL)
	free (*credp);
    }

  *whop = who->binddn ? strdup (who->binddn) : NULL;
  *credp = who->bindpw ? strdup (who->bindpw) : NULL;

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif

NSS_STATUS
_nss_ldap_proxy_bind (const char *user, const char *password)
{
  ldap_args_t args;
  LDAPMessage *res, *e;
  NSS_STATUS stat;
  int rc;
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_proxy_bind_args_t proxy_args_buf;
  ldap_proxy_bind_args_t *proxy_args = &proxy_args_buf;
#else
  ldap_proxy_bind_args_t *proxy_args = &__proxy_args;
#endif
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_proxy_bind");

  LA_INIT (args);
  LA_TYPE (args) = LA_TYPE_STRING;
  LA_STRING (args) = user;

  /*
   * Binding with an empty password will always work, so don't let
   * the user in if they try that.
   */
  if (password == NULL || password[0] == '\0')
    {
      debug ("<== _nss_ldap_proxy_bind (empty password not permitted)");
      /* XXX overload */
      return NSS_TRYAGAIN;
    }

  _nss_ldap_enter ();

  stat = _nss_ldap_search_s (&args, _nss_ldap_filt_getpwnam,
			     LM_PASSWD, NULL, 1, &res);
  if (stat == NSS_SUCCESS)
    {
      e = _nss_ldap_first_entry (res);
      if (e != NULL)
	{
	  proxy_args->binddn = _nss_ldap_get_dn (e);
	  proxy_args->bindpw = password;

	  if (proxy_args->binddn != NULL)
	    {
	      /* Use our special rebind procedure. */
#if LDAP_SET_REBIND_PROC_ARGS == 3
	      ldap_set_rebind_proc (session->ls_conn, do_proxy_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
	      ldap_set_rebind_proc (session->ls_conn, do_proxy_rebind);
#endif

	      debug (":== _nss_ldap_proxy_bind: %s", proxy_args->binddn);

	      rc = do_bind (session,
			    session->ls_config->ldc_bind_timelimit,
			    proxy_args->binddn, proxy_args->bindpw, 0);
	      switch (rc)
		{
		case LDAP_INVALID_CREDENTIALS:
		  /* XXX overload */
		  stat = NSS_TRYAGAIN;
		  break;
		case LDAP_NO_SUCH_OBJECT:
		  stat = NSS_NOTFOUND;
		  break;
		case LDAP_SUCCESS:
		  stat = NSS_SUCCESS;
		  break;
		default:
		  stat = NSS_UNAVAIL;
		  break;
		}
	      /*
	       * Close the connection, don't want to continue
	       * being bound as this user or using this rebind proc.
	       */
	      do_close (session);
	      ldap_memfree (proxy_args->binddn);
	    }
	  else
	    {
	      stat = NSS_NOTFOUND;
	    }
	  proxy_args->binddn = NULL;
	  proxy_args->bindpw = NULL;
	}
      else
	{
	  stat = NSS_NOTFOUND;
	}
      ldap_msgfree (res);
    }

  _nss_ldap_leave ();

  debug ("<== _nss_ldap_proxy_bind");

  return stat;
}

static int
do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *_interact)
{
  char *authzid = (char *) defaults;
  sasl_interact_t *interact = (sasl_interact_t *) _interact;
  int rc = LDAP_SUCCESS;

  debug("==> do_sasl_interact flags=%d, defaults=%s, _interact=%p", flags, authzid, _interact);

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) ||defined (HAVE_SASL_SASL_H))
  while (interact->id != SASL_CB_LIST_END)
    {
      if (interact->id == SASL_CB_USER)
	{
	  if (authzid != NULL)
	    {
	      interact->result = authzid;
	      interact->len = strlen (authzid);
	    }
	  else if (interact->defresult != NULL)
	    {
	      interact->result = interact->defresult;
	      interact->len = strlen (interact->defresult);
	    }
	  else
	    {
	      interact->result = "";
	      interact->len = 0;
	    }
#if SASL_VERSION_MAJOR < 2
	  interact->result = strdup (interact->result);
	  if (interact->result == NULL)
	    {
	      rc = LDAP_NO_MEMORY;
	      break;
	    }
#endif /* SASL_VERSION_MAJOR < 2 */
	}
      else
	{
	  rc = LDAP_PARAM_ERROR;
	  break;
	}
      interact++;
    }
#endif

  debug ("<== do_sasl_interact rc=%d", rc);

  return rc;
}

const char **
_nss_ldap_get_attributes (ldap_map_selector_t sel)
{
  const char **attrs = NULL;
  ldap_session_t *session = &__session;

  debug ("==> _nss_ldap_get_attributes");

  if (sel < LM_NONE)
    {
      NSS_STATUS stat;

      stat = do_check_init (session);

      if (stat != NSS_SUCCESS)
	{
	  if (do_init (session) != NSS_SUCCESS)
	    {
	      debug ("<== _nss_ldap_get_attributes: session initialization failed");
	      return NULL;
	    }
	}
      attrs = session->ls_config->ldc_attrtab[sel];
    }

  debug ("<== _nss_ldap_get_attributes");

  return attrs;
}

int
_nss_ldap_test_config_flag (unsigned int flag)
{
  ldap_session_t *session = &__session;

  if (session->ls_config != NULL && (session->ls_config->ldc_flags & flag) != 0)
    return 1;

  return 0;
}

int
_nss_ldap_test_initgroups_ignoreuser (const char *user)
{
  ldap_session_t *session = &__session;
  char **p;

  if (session->ls_config == NULL)
    return 0;

  if (session->ls_config->ldc_initgroups_ignoreusers == NULL)
    return 0;

  for (p = session->ls_config->ldc_initgroups_ignoreusers; *p != NULL; p++)
    {
      if (strcmp (*p, user) == 0)
	return 1;
    }

  return 0;
}

int
_nss_ldap_get_ld_errno (char **m, char **s)
{
  int rc;
  int lderrno;
  ldap_session_t *session = &__session;

  if (session->ls_conn == NULL)
    {
      return LDAP_UNAVAILABLE;
    }

  if ((rc = GET_ERROR_NUMBER (session->ls_conn, &lderrno)) != LDAP_OPT_SUCCESS)
    {
      return rc;
    }

  if (s != NULL)
    {
      if ((rc = GET_ERROR_STRING (session->ls_conn, s)) != LDAP_OPT_SUCCESS)
	{
	  return rc;
	}
    }

  if (m != NULL)
    {
      if ((rc = GET_MATCHED_DN (session->ls_conn, m)) != LDAP_SUCCESS)
	{
	  return rc;
	}
    }

  return lderrno;
}

/*
 * This provides support for opaque extension objects which are used to support
 * kerberos data structures among other things
 */
ldap_session_opaque_t
__nss_ldap_find_opaque (ldap_session_t *session,
			ldap_session_opaque_type_t opaque_type)
{
  ldap_session_opaque_t current = session->ls_opaque;

  while (current != NULL)
    {
      if (current->lso_type == opaque_type)
	{
	  return current;
	}
      current = current->lso_next;
    }

  return NULL;
}

ldap_session_opaque_t
__nss_ldap_add_opaque (ldap_session_t *session,
		       ldap_session_opaque_type_t opaque_type,
		       ldap_session_opaque_t current)
{
  ldap_session_opaque_t head = session->ls_opaque;

  __nss_ldap_free_opaque( session, opaque_type);

  if (current != NULL)
    {
      current->lso_type = opaque_type;
      current->lso_next = head;
      if (head != NULL)
	{
	  head->lso_prev = current;
	}
      session->ls_opaque = current;
    }

  return current;
}

ldap_session_opaque_t
__nss_ldap_allocate_opaque (ldap_session_t *session,
			    ldap_session_opaque_type_t opaque_type)
{
  ldap_session_opaque_t current;

  current = __nss_ldap_find_opaque (session, opaque_type);
  if (current != NULL)
    {
      return current;
    }

  current = (ldap_session_opaque_t) calloc (1, sizeof (struct ldap_session_opaque));
  if (current == NULL)
    {
      return NULL;
    }

  return __nss_ldap_add_opaque (session, opaque_type, current);
}

ldap_session_opaque_t
__nss_ldap_remove_opaque (ldap_session_t *session, ldap_session_opaque_type_t opaque_type)
{
  ldap_session_opaque_t head = session->ls_opaque;
  ldap_session_opaque_t current;

  current = __nss_ldap_find_opaque (session, opaque_type);
  if (current != NULL)
    {
      if (current->lso_prev != NULL)
	{
	  current->lso_prev->lso_next = current->lso_next;
	}
      if (current->lso_next != NULL)
	{
	  current->lso_next->lso_prev = current->lso_prev;
	}
      if (current == head)
	{
	  session->ls_opaque = current->lso_next;
	}
      current->lso_next = current->lso_prev = NULL;
    }

  return current;
}

void
__nss_ldap_free_opaque (ldap_session_t *session, ldap_session_opaque_type_t opaque_type)
{
  ldap_session_opaque_t current = __nss_ldap_remove_opaque (session, opaque_type);

  if (current != NULL)
    {
      if (current->lso_data != NULL)
	{
	  free(current->lso_data);
	}
      free (current);
    }
}

/*
 * Support for SASL mechanism features
 */
ldap_session_mech_t
__nss_ldap_mech_setup (ldap_session_mech_type_t mechType,
		       ldap_session_mech_init_t initFunc,
		       ldap_session_mech_select_t selectFunc,
		       ldap_session_mech_restore_t restoreFunc,
		       ldap_session_mech_close_t closeFunc)
{
  ldap_session_mech_t mech = NULL;

  debug ("==> __nss_ldap_do_mech_setup: %d", mechType);

  mech = (ldap_session_mech_t)malloc (sizeof (*mech));
  if (mech != NULL)
    {
      mech->lsm_type = mechType;
      mech->lsm_init = initFunc;
      mech->lsm_select = selectFunc;
      mech->lsm_restore = restoreFunc;
      mech->lsm_close = closeFunc;
    }
  else
    {
      debug ("==> __nss_ldap_do_mech_setup: memory allocation failed");
    }

  debug ("<== __nss_ldap_do_mech_setup: returns %p", mech);

  return mech;
}
