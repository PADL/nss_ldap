/* Copyright (C) 1997-2003 Luke Howard.
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

#ifdef HAVE_THREAD_H
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
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
#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#elif defined(HAVE_SASL_H)
#include <sasl.h>
#endif
#ifdef AT_OC_MAP
#ifdef HAVE_DB3_DB_185_H
#include <db3/db_185.h>
#elif defined(HAVE_DB_185_H)
#include <db_185.h>
#elif defined(HAVE_DB1_DB_H)
#include <db1/db.h>
#elif defined(HAVE_DB_H)
#include <db.h>
#else
#error Schema mapping requires the Berkeley DB library.
#endif /* DB */
#endif /* AT_OC_MAP */

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "ltf.h"
#include "util.h"
#include "dnsconfig.h"

#ifdef PAGE_RESULTS
#include "pagectrl.h"
#endif

#ifdef HAVE_THREAD_H
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
static ldap_config_t *__config = NULL;

#ifdef HAVE_SIGPROCMASK
static sigset_t __signal_mask;
static int __sigprocmask_retval;
#else
static void (*__sigpipe_handler) (int) = SIG_DFL;
#endif /* HAVE_SIGPROCMASK */

/*
 * Global LDAP session.
 */
static ldap_session_t __session = { NULL, NULL, 0 };

#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
static pthread_once_t __once = PTHREAD_ONCE_INIT;
#endif

#ifndef HAVE_PTHREAD_ATFORK
/* 
 * Process ID that opened the session.
 */
static pid_t __pid = -1;
#endif
static uid_t __euid = -1;

#ifdef HAVE_LDAPSSL_CLIENT_INIT
static int __ssl_initialized = 0;
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
/*
 * Prepare for fork(); lock mutex.
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
static void do_close (void);

/*
 * Close the global session without sending an unbind.
 */
static void do_close_no_unbind (void);

/*
 * Disable keepalive on a LDAP connection's socket.
 */
static void do_set_sockopts (void);

/*
 * TLS routines: set global SSL session options.
 */
#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int do_ssl_options (ldap_config_t * cfg);
#endif

/*
 * Open the global session
 */
static NSS_STATUS do_open (void);

/*
 * Perform an asynchronous search.
 */
static int do_search (const char *base, int scope,
		      const char *filter, const char **attrs,
		      int sizelimit, int *);

/*
 * Perform a synchronous search.
 */
static int do_search_s (const char *base, int scope,
			const char *filter, const char **attrs,
			int sizelimit, LDAPMessage **);

/*
 * Fetch an LDAP result.
 */
static NSS_STATUS do_result (ent_context_t * ctx, int all);

/*
 * Format a filter given a prototype.
 */
static NSS_STATUS do_filter (const ldap_args_t * args, const char *filterprot,
			     ldap_service_search_descriptor_t * sd,
			     char *filter, size_t filterlen,
			     const char **retFilter);

/*
 * Parse a result, fetching new results until a successful parse
 * or exceptional condition.
 */
static NSS_STATUS do_parse (ent_context_t * ctx, void *result, char *buffer,
			    size_t buflen, int *errnop, parser_t parser);

/*
 * Parse a result, fetching results from the result chain 
 * rather than the server.
 */
static NSS_STATUS do_parse_s (ent_context_t * ctx, void *result, char *buffer,
			      size_t buflen, int *errnop, parser_t parser);

/*
 * Function to be braced by reconnect harness. Used so we
 * can apply the reconnect code to both asynchronous and
 * synchronous searches.
 */
typedef int (*search_func_t) (const char *, int, const char *,
			      const char **, int, void *);

/*
 * Do a search with a reconnect harness.
 */
static NSS_STATUS
do_with_reconnect (const char *base, int scope,
		   const char *filter, const char **attrs, int sizelimit,
		   void *private, search_func_t func);

/*
 * Do a bind with a defined timeout
 */
static int do_bind (LDAP * ld, int timelimit, const char *dn, const char *pw,
		    int with_sasl);

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
static int do_sasl_interact (LDAP * ld, unsigned flags, void *defaults,
			     void *p);
#endif

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
  char *who, *cred;
  int timelimit;
  int with_sasl = 0;

  if (geteuid () == 0 && __session.ls_config->ldc_rootbinddn)
    {
      who = __session.ls_config->ldc_rootbinddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_rootusesasl;
      if (with_sasl)
	{
	  cred = __session.ls_config->ldc_rootsaslid;
	}
      else
	{
#endif
	  cred = __session.ls_config->ldc_rootbindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
	}
#endif
    }
  else
    {
      who = __session.ls_config->ldc_binddn;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_usesasl;
      if (with_sasl)
	{
	  cred = __session.ls_config->ldc_saslid;
	}
      else
	{
#endif
	  cred = __session.ls_config->ldc_bindpw;
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
	}
#endif
    }

  timelimit = __session.ls_config->ldc_bind_timelimit;

  return do_bind (ld, timelimit, who, cred, with_sasl);
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
  if (freeit)
    {
      if (*whop != NULL)
	free (*whop);
      if (*credp != NULL)
	free (*credp);
    }

  *whop = *credp = NULL;
  if (geteuid () == 0 && __session.ls_config->ldc_rootbinddn)
    {
      *whop = strdup (__session.ls_config->ldc_rootbinddn);
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_rootusesasl;
      if (with_sasl && __session.ls_config->ldc_rootsaslid)
	{
	  *credp = __session.ls_config->ldc_rootsaslid;
	}
      else
#endif
      if (__session.ls_config->ldc_rootbindpw)
	*credp = strdup (__session.ls_config->ldc_rootbindpw);
    }
  else
    {
      if (__session.ls_config->ldc_binddn != NULL)
	*whop = strdup (__session.ls_config->ldc_binddn);
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      with_sasl = __session.ls_config->ldc_usesasl;
      if (with_sasl && __session.ls_config->ldc_saslid)
	{
	  *credp = __session.ls_config->ldc_saslid;
	}
      else
#endif
      if (__session.ls_config->ldc_bindpw != NULL)
	*credp = strdup (__session.ls_config->ldc_bindpw);
    }

  *methodp = LDAP_AUTH_SIMPLE;

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
      _nss_ldap_ent_context_release ((((nss_ldap_backend_t *) be)->state));
      free ((((nss_ldap_backend_t *) be)->state));
      ((nss_ldap_backend_t *) be)->state = NULL;
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

  debug ("<== _nss_ldap_default_constr");

  return NSS_SUCCESS;
}
#endif /* HAVE_NSSWITCH_H */

#if defined(HAVE_PTHREAD_ATFORK) || defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
static void
do_atfork_prepare (void)
{
  debug ("==> do_atfork_prepare");
  NSS_LDAP_LOCK (__lock);
  debug ("<== do_atfork_prepare");
}

static void
do_atfork_parent (void)
{
  debug ("==> do_atfork_parent");
  NSS_LDAP_UNLOCK (__lock);
  debug ("<== do_atfork_parent");
}

static void
do_atfork_child (void)
{
  debug ("==> do_atfork_child");
  do_close_no_unbind ();
  NSS_LDAP_UNLOCK (__lock);
  debug ("<== do_atfork_child");
}

static void
do_atfork_setup (void)
{
  debug ("==> do_atfork_setup");

#ifdef HAVE_PTHREAD_ATFORK
  (void) pthread_atfork (do_atfork_prepare, do_atfork_parent,
			 do_atfork_child);
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  (void) __libc_atfork (do_atfork_prepare, do_atfork_parent, do_atfork_child);
#endif

  debug ("<== do_atfork_setup");
}
#endif

/*
 * Acquires global lock, blocks SIGPIPE.
 */
void
_nss_ldap_enter (void)
{
#ifdef HAVE_SIGPROCMASK
  sigset_t sigset;
#endif

  debug ("==> _nss_ldap_enter");

  NSS_LDAP_LOCK (__lock);

  /*
   * Patch for Debian Bug 130006:
   * ignore SIGPIPE for all LDAP operations.
   */
#ifdef HAVE_SIGPROCMASK
  sigemptyset (&sigset);
  sigaddset (&sigset, SIGPIPE);
  __sigprocmask_retval = sigprocmask (SIG_BLOCK, &sigset, &__signal_mask);
#elif defined(HAVE_SIGSET)
  __sigpipe_handler = sigset (SIGPIPE, SIG_IGN);
#else
  __sigpipe_handler = signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */

  debug ("<== _nss_ldap_enter");
}

/*
 * Releases global mutex, releases SIGPIPE.
 */
void
_nss_ldap_leave (void)
{
  debug ("==> _nss_ldap_leave");

  /*
   * Restore signal handler for SIGPIPE.
   */
#ifdef HAVE_SIGPROCMASK
  if (__sigprocmask_retval == 0)
    sigprocmask (SIG_SETMASK, &__signal_mask, NULL);
#else
  if (__sigpipe_handler != SIG_ERR && __sigpipe_handler != SIG_IGN)
    {
# ifdef HAVE_SIGSET
      (void) sigset (SIGPIPE, __sigpipe_handler);
# else
      (void) signal (SIGPIPE, __sigpipe_handler);
# endif	/* HAVE_SIGSET */
    }
#endif /* HAVE_SIGPROCMASK */

  NSS_LDAP_UNLOCK (__lock);

  debug ("<== _nss_ldap_leave");
}

static void
do_set_sockopts (void)
{
/*
 * Netscape SSL-enabled LDAP library does not
 * return the real socket.
 */
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  int sd = -1;

  debug ("==> do_set_sockopts");
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_DESC)
  if (ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd) == 0)
#else
  if ((sd = __session.ls_conn->ld_sb.sb_sd) > 0)
#endif /* LDAP_OPT_DESC */
    {
      int off = 0;
#ifdef HAVE_SOCKLEN_T
      socklen_t namelen = sizeof (struct sockaddr);
#else
      int namelen = sizeof (struct sockaddr);
#endif

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
       * sockaddr_in structures for later comparison in do_close_no_unbind ().
       */
      (void) getsockname (sd, &__session.ls_sockname, &namelen);
      (void) getpeername (sd, &__session.ls_peername, &namelen);
    }
  debug ("<== do_set_sockopts");
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

  return;
}

/*
 * Closes connection to the LDAP server.
 * This assumes that we have exclusive access to __session.ls_conn,
 * either by some other function having acquired a lock, or by
 * using a thread safe libldap.
 */
static void
do_close (void)
{
  debug ("==> do_close");

  if (__session.ls_conn != NULL)
    {
#ifdef DEBUG
      syslog (LOG_DEBUG, "nss_ldap: closing connection %p",
	      __session.ls_conn);
#endif /* DEBUG */
      ldap_unbind (__session.ls_conn);
      __session.ls_conn = NULL;
    }

  debug ("<== do_close");
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
do_close_no_unbind (void)
{
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  int sd = -1;
#endif /* HAVE_LDAPSSL_CLIENT_INIT */
#ifndef HAVE_LDAP_LD_FREE
  int bogusSd = -1;
#endif /* HAVE_LDAP_LD_FREE */

  debug ("==> do_close_no_unbind");

  if (__session.ls_conn == NULL)
    {
      debug ("<== do_close_no_unbind (connection was not open)");
      return;
    }

#ifdef DEBUG
  syslog (LOG_DEBUG, "nss_ldap: closing connection (no unbind) %p",
	  __session.ls_conn);
#endif /* DEBUG */

  /*
   * Before freeing the LDAP context or closing the socket descriptor, we
   * must ensure that it is *our* socket descriptor.  See the much lengthier
   * description of this at the end of do_open () where the values
   * __session.ls_sockname and __session.ls_peername are saved.
   */
#ifndef HAVE_LDAPSSL_CLIENT_INIT
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_DESC)
  if (ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd) == 0)
#else
  if ((sd = __session.ls_conn->ld_sb.sb_sd) > 0)
#endif /* LDAP_OPT_DESC */
    {
      struct sockaddr sockname;
      struct sockaddr peername;
#ifdef HAVE_SOCKLEN_T
      socklen_t socknamelen = sizeof (sockname);
      socklen_t peernamelen = sizeof (peername);
#else
      int socknamelen = sizeof (sockname);
      int peernamelen = sizeof (peername);
#endif /* HAVE_SOCKLEN_T */

      /*
       * Important to perform comparison "family-aware" to not count
       * sin_zero padding as significant.
       */
      if (getsockname (sd, &sockname, &socknamelen) != 0)
	{
	  __session.ls_conn = NULL;
	  debug ("<== do_close_no_unbind (could not get socket name)");
	  return;
	}
      if (sockname.sa_family != __session.ls_sockname.sa_family)
	{
	  __session.ls_conn = NULL;
	  debug ("<== do_close_no_unbind (socket family differs)");
	  return;
	}
      switch (sockname.sa_family)
	{
	case AF_INET:
	  if (((struct sockaddr_in *) &sockname)->sin_port !=
	      ((struct sockaddr_in *) &__session.ls_sockname)->sin_port)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket port differs)");
	      return;
	    }
	  if (memcmp
	      (&((struct sockaddr_in *) &sockname)->sin_addr,
	       &((struct sockaddr_in *) &__session.ls_sockname)->sin_addr,
	       sizeof (struct in_addr)) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket address differs)");
	      return;
	    }
	  break;
#ifdef INET6
	case AF_INET6:
	  if (((struct sockaddr_in6 *) &sockname)->sin6_port !=
	      ((struct sockaddr_in6 *) &__session.ls_sockname)->sin6_port)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket port differs)");
	      return;
	    }
	  if (memcmp
	      (&((struct sockaddr_in6 *) &sockname)->sin6_addr,
	       &((struct sockaddr_in6 *) &__session.ls_sockname)->sin6_addr,
	       sizeof (struct in6_addr)) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket address differs)");
	      return;
	    }
	  if (((struct sockaddr_in6 *) &sockname)->sin6_scope_id !=
	      ((struct sockaddr_in6 *) &__session.ls_sockname)->sin6_scope_id)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket scope ID differs)");
	      return;
	    }
	  break;
#endif /* INET6 */
	case AF_UNIX:
	  if (strcmp
	      (((struct sockaddr_un *) &sockname)->sun_path,
	       ((struct sockaddr_un *) &__session.ls_sockname)->sun_path) !=
	      0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket path differs)");
	      return;
	    }
	  break;
	default:
	  if (memcmp (&sockname, &__session.ls_sockname, socknamelen) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (socket data differs)");
	      return;
	    }
	  break;
	}
      if (getpeername (sd, &peername, &peernamelen) != 0)
	{
	  __session.ls_conn = NULL;
	  debug ("<== do_close_no_unbind (could not get peer name)");
	  return;
	}
      switch (peername.sa_family)
	{
	case AF_INET:
	  if (((struct sockaddr_in *) &peername)->sin_port !=
	      ((struct sockaddr_in *) &__session.ls_peername)->sin_port)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer port differs)");
	      return;
	    }
	  if (memcmp
	      (&((struct sockaddr_in *) &peername)->sin_addr,
	       &((struct sockaddr_in *) &__session.ls_peername)->sin_addr,
	       sizeof (struct in_addr)) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer address differs)");
	      return;
	    }
	  break;
#ifdef INET6
	case AF_INET6:
	  if (((struct sockaddr_in6 *) &peername)->sin6_port !=
	      ((struct sockaddr_in6 *) &__session.ls_peername)->sin6_port)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer port differs)");
	      return;
	    }
	  if (memcmp
	      (&((struct sockaddr_in6 *) &peername)->sin6_addr,
	       &((struct sockaddr_in6 *) &__session.ls_peername)->sin6_addr,
	       sizeof (struct in6_addr)) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer address differs)");
	      return;
	    }
	  if (((struct sockaddr_in6 *) &peername)->sin6_scope_id !=
	      ((struct sockaddr_in6 *) &__session.ls_peername)->sin6_scope_id)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer scope ID differs)");
	      return;
	    }
	  break;
#endif /* INET6 */
	case AF_UNIX:
	  if (strcmp
	      (((struct sockaddr_un *) &peername)->sun_path,
	       ((struct sockaddr_un *) &__session.ls_peername)->sun_path) !=
	      0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer path differs)");
	      return;
	    }
	  break;
	default:
	  if (memcmp (&peername, &__session.ls_peername, peernamelen) != 0)
	    {
	      __session.ls_conn = NULL;
	      debug ("<== do_close_no_unbind (peer data differs)");
	      return;
	    }
	  break;
	}
    }
#endif /* HAVE_LDAPSSL_CLIENT_INIT */

#ifdef HAVE_LDAP_LD_FREE

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
  (void) ldap_ld_free (__session.ls_conn, 0, NULL, NULL);
#else
  (void) ldap_ld_free (__session.ls_conn, 0);
#endif /* OPENLDAP 2.x */

#else
#ifndef HAVE_LDAPSSL_CLIENT_INIT
  if (sd > 0)
    close (sd);
#endif /* HAVE_LDAPSSL_CLIENT_INIT */
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DESC)
  (void) ldap_set_option (__session.ls_conn, LDAP_OPT_DESC, &bogusSd);
#else
  __session.ls_conn->ld_sb.sb_sd = bogusSd;
#endif /* LDAP_OPT_DESC */

  /* hope we closed it OK! */
  ldap_unbind (__session.ls_conn);

#endif /* HAVE_LDAP_LD_FREE */

  __session.ls_conn = NULL;

  debug ("<== do_close_no_unbind");

  return;
}

/*
 * A simple alias around do_open().
 */
NSS_STATUS
_nss_ldap_init (void)
{
  return do_open ();
}

/*
 * Opens connection to an LDAP server.
 * As with do_close(), this assumes ownership of sess.
 * It also wants to own __config: is there a potential deadlock here? XXX
 */
static NSS_STATUS
do_open (void)
{
  ldap_config_t *cfg = NULL;
  uid_t euid;
#ifndef HAVE_PTHREAD_ATFORK
  pid_t pid;
#endif
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  int timeout;
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
  struct timeval tv;
#endif
  int usesasl;
  char *bindarg;

  debug ("==> do_open");

#ifndef HAVE_PTHREAD_ATFORK
#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  /*
   * This bogosity is necessary because Linux uses different
   * PIDs for different threads (like IRIX, which we don't
   * support). We can tell whether we are linked against
   * libpthreads by whether __pthread_atfork is NULL or
   * not. If it is NULL, then we're not linked with the
   * threading library, and we need to compare the current
   * process ID against the saved one to figure out
   * whether we've forked. 
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
  if (__pthread_atfork == NULL)
    pid = getpid ();
  else
    pid = -1;			/* linked against libpthreads, don't care */
#else
  pid = getpid ();
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
#endif /* HAVE_PTHREAD_ATFORK */

  euid = geteuid ();

#ifdef DEBUG
#ifdef HAVE_PTHREAD_ATFORK
  syslog (LOG_DEBUG,
	  "nss_ldap: __session.ls_conn=%p, __euid=%i, euid=%i",
	  __session.ls_conn, __euid, euid);
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  syslog (LOG_DEBUG,
	  "nss_ldap: libpthreads=%s, __session.ls_conn=%p, __pid=%i, pid=%i, __euid=%i, euid=%i",
	  (__pthread_atfork == NULL ? "FALSE" : "TRUE"),
	  __session.ls_conn,
	  (__pthread_atfork == NULL ? __pid : -1),
	  (__pthread_atfork == NULL ? pid : -1), __euid, euid);
#else
  syslog (LOG_DEBUG,
	  "nss_ldap: __session.ls_conn=%p, __pid=%i, pid=%i, __euid=%i, euid=%i",
	  __session.ls_conn, __pid, pid, __euid, euid);
#endif
#endif /* DEBUG */

#ifndef HAVE_PTHREAD_ATFORK
#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  if (__pthread_atfork == NULL && __pid != pid)
#else
  if (__pid != pid)
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
    {
      do_close_no_unbind ();
    }
  else
#endif /* HAVE_PTHREAD_ATFORK */
  if (__euid != euid && (__euid == 0 || euid == 0))
    {
      /*
       * If we've changed user ids, close the session so we can
       * rebind as the correct user.
       */
      do_close ();
    }
  else if (__session.ls_conn != NULL && __session.ls_config != NULL)
    {
      /*
       * Patch from Steven Barrus <sbarrus@eng.utah.edu> to
       * close the session after an idle timeout.
       */
      time_t current_time;
      /*
       * Otherwise we can hand back this process' global
       * LDAP session.
       *
       * Patch from Steven Barrus <sbarrus@eng.utah.edu> to
       * close the session after an idle timeout. 
       */
      if (__session.ls_config->ldc_idle_timelimit)
	{
	  time (&current_time);
	  if ((__session.ls_timestamp +
	       __session.ls_config->ldc_idle_timelimit) < current_time)
	    {
	      debug ("idle_timelimit reached");
	      do_close ();
	    }
	}

      /*
       * If the connection is still there (ie. do_close() wasn't
       * called) then we can return the cached connection.
       */
      if (__session.ls_conn != NULL)
	{
	  debug ("<== do_open");
	  return NSS_SUCCESS;
	}
    }

#ifdef HAVE_PTHREAD_ATFORK
  if (pthread_once (&__once, do_atfork_setup) != 0)
    {
      debug ("<== do_open");
      return NSS_UNAVAIL;
    }
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
  /*
   * Only install the pthread_atfork() handlers i
   * we are linked against libpthreads. Otherwise,
   * do close the session when the PID changes.
   */
  if (__pthread_atfork == NULL)
    __pid = pid;
  else
    __libc_once (__once, do_atfork_setup);
#else
  __pid = pid;
#endif

  __euid = euid;
  memset (&__session, 0, sizeof (__session));

  if (__config == NULL)
    {
      NSS_STATUS stat;

      stat =
	_nss_ldap_readconfig (&__config, __configbuf, sizeof (__configbuf));

      if (stat != NSS_SUCCESS)
	{
	  __config = NULL;	/* reset otherwise heap is corrupted */
	  stat =
	    _nss_ldap_readconfigfromdns (&__config, __configbuf,
					 sizeof (__configbuf));
	}

      if (stat != NSS_SUCCESS)
	{
	  __config = NULL;
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }

  cfg = __config;

  _nss_ldap_init_attributes (cfg->ldc_attrtab);
  _nss_ldap_init_filters ();

  while (1)
    {
#ifdef HAVE_LDAPSSL_CLIENT_INIT
      /*
       * Initialize the SSL library. 
       */
      if (cfg->ldc_ssl_on == SSL_LDAPS)
	{
	  if (__ssl_initialized == 0
	      && ldapssl_client_init (cfg->ldc_sslpath, NULL) != LDAP_SUCCESS)
	    {
	      break;
	    }
	  __ssl_initialized = 1;
	}
#endif /* SSL */
#ifdef HAVE_LDAP_INITIALIZE
      __session.ls_conn = NULL;
      if (cfg->ldc_uri != NULL)
	{
	  int rc;
	  debug ("==> ldap_initialize");
	  rc = ldap_initialize (&__session.ls_conn, cfg->ldc_uri);
	  debug ("<== ldap_initialize");

	  if (rc != LDAP_SUCCESS)
	    {
	      break;
	    }
	}
      else
	{
#endif /* HAVE_LDAP_INITIALIZE */
#ifdef HAVE_LDAP_INIT
	  debug ("==> ldap_init");
	  __session.ls_conn = ldap_init (cfg->ldc_host, cfg->ldc_port);
	  debug ("<== ldap_init");
#else
	  debug ("==> ldap_open");
	  __session.ls_conn = ldap_open (cfg->ldc_host, cfg->ldc_port);
	  debug ("<== ldap_open");
#endif /* HAVE_LDAP_INIT */
#ifdef HAVE_LDAP_INITIALIZE
	}
#endif
      if (__session.ls_conn != NULL || cfg->ldc_next == cfg)
	{
	  break;
	}
      cfg = cfg->ldc_next;
    }

  if (__session.ls_conn == NULL)
    {
      debug ("<== do_open");
      return NSS_UNAVAIL;
    }

#ifdef LDAP_OPT_THREAD_FN_PTRS
  if (_nss_ldap_ltf_thread_init (__session.ls_conn) != NSS_SUCCESS)
    {
      do_close ();
      debug ("<== do_open");
      return NSS_UNAVAIL;
    }
#endif /* LDAP_OPT_THREAD_FN_PTRS */

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (__session.ls_conn, do_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (__session.ls_conn, do_rebind);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
  ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
		   &cfg->ldc_version);
#else
  __session.ls_conn->ld_version = cfg->ldc_version;
#endif /* LDAP_OPT_PROTOCOL_VERSION */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DEREF)
  ldap_set_option (__session.ls_conn, LDAP_OPT_DEREF, &cfg->ldc_deref);
#else
  __session.ls_conn->ld_deref = cfg->ldc_deref;
#endif /* LDAP_OPT_DEREF */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMELIMIT)
  ldap_set_option (__session.ls_conn, LDAP_OPT_TIMELIMIT,
		   &cfg->ldc_timelimit);
#else
  __session.ls_conn->ld_timelimit = cfg->ldc_timelimit;
#endif /* LDAP_OPT_TIMELIMIT */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_X_OPT_CONNECT_TIMEOUT)
  /*
   * This is a new option in the Netscape SDK which sets
   * the TCP connect timeout. For want of a better value,
   * we use the bind_timelimit to control this.
   */
  timeout = cfg->ldc_bind_timelimit * 1000;
  ldap_set_option (__session.ls_conn, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
#endif /* LDAP_X_OPT_CONNECT_TIMEOUT */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
  tv.tv_sec = cfg->ldc_bind_timelimit;
  tv.tv_usec = 0;
  ldap_set_option (__session.ls_conn, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif /* LDAP_OPT_NETWORK_TIMEOUT */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_REFERRALS)
  ldap_set_option (__session.ls_conn, LDAP_OPT_REFERRALS,
		   cfg->ldc_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_RESTART)
  ldap_set_option (__session.ls_conn, LDAP_OPT_RESTART,
		   cfg->ldc_restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#ifdef HAVE_LDAP_START_TLS_S
  if (cfg->ldc_ssl_on == SSL_START_TLS)
    {
      int version;

      if (ldap_get_option
	  (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
	   &version) == LDAP_OPT_SUCCESS)
	{
	  if (version < LDAP_VERSION3)
	    {
	      version = LDAP_VERSION3;
	      ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
			       &version);
	    }
	}

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
	{
	  debug ("Setting of SSL options failed");
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}

      debug ("==> start_tls");
      if (ldap_start_tls_s (__session.ls_conn, NULL, NULL) == LDAP_SUCCESS)
	{
	  debug ("TLS startup succeeded");
	}
      else
	{
	  debug ("TLS startup failed");
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
      debug ("<== start_tls");
    }
  else
#endif /* HAVE_LDAP_START_TLS_S */

    /*
     * If SSL is desired, then enable it.
     */
  if (cfg->ldc_ssl_on == SSL_LDAPS)
    {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
      int tls = LDAP_OPT_X_TLS_HARD;
      if (ldap_set_option (__session.ls_conn, LDAP_OPT_X_TLS, &tls) !=
	  LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}

      /* set up SSL context */
      if (do_ssl_options (cfg) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}

#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
      if (ldapssl_install_routines (__session.ls_conn) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
/* not in Solaris 9? */
#ifndef LDAP_OPT_SSL
#define LDAP_OPT_SSL 0x0A
#endif
      if (ldap_set_option (__session.ls_conn, LDAP_OPT_SSL, LDAP_OPT_ON) !=
	  LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
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
  if (euid == 0 && cfg->ldc_rootbinddn != NULL)
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = cfg->ldc_rootusesasl;
      bindarg =
	cfg->ldc_rootusesasl ? cfg->ldc_rootsaslid : cfg->ldc_rootbindpw;
#else
      usesasl = 0;
      bindarg = cfg->ldc_rootbindpw;
#endif

      if (do_bind
	  (__session.ls_conn, cfg->ldc_bind_timelimit, cfg->ldc_rootbinddn,
	   bindarg, usesasl) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }
  else
    {
#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
      usesasl = cfg->ldc_usesasl;
      bindarg = cfg->ldc_usesasl ? cfg->ldc_saslid : cfg->ldc_bindpw;
#else
      usesasl = 0;
      bindarg = cfg->ldc_bindpw;
#endif

      if (do_bind
	  (__session.ls_conn, cfg->ldc_bind_timelimit, cfg->ldc_binddn,
	   cfg->ldc_bindpw, usesasl) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }

  do_set_sockopts ();

  __session.ls_config = cfg;

  time (&__session.ls_timestamp);

  debug ("<== do_open");

  return NSS_SUCCESS;
}

#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
static int
do_ssl_options (ldap_config_t * cfg)
{
  int rc;

  debug ("==> do_ssl_options");

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
  if (cfg->ldc_tls_randfile != NULL)
    {
      /* rand file */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
			    cfg->ldc_tls_randfile);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_RANDOM_FILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

  if (cfg->ldc_tls_cacertfile != NULL)
    {
      /* ca cert file */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE,
			    cfg->ldc_tls_cacertfile);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_cacertdir != NULL)
    {
      /* ca cert directory */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR,
			    cfg->ldc_tls_cacertdir);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CACERTDIR failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  /* require cert? */
  rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
			&cfg->ldc_tls_checkpeer);
  if (rc != LDAP_SUCCESS)
    {
      debug
	("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_REQUIRE_CERT failed");
      return LDAP_OPERATIONS_ERROR;
    }

  if (cfg->ldc_tls_ciphers != NULL)
    {
      /* set cipher suite, certificate and private key: */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
			    cfg->ldc_tls_ciphers);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CIPHER_SUITE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_cert != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, cfg->ldc_tls_cert);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_CERTFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (cfg->ldc_tls_key != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, cfg->ldc_tls_key);
      if (rc != LDAP_SUCCESS)
	{
	  debug
	    ("<== do_ssl_options: Setting of LDAP_OPT_X_TLS_KEYFILE failed");
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  debug ("<== do_ssl_options");

  return LDAP_SUCCESS;
}
#endif

static int
do_bind (LDAP * ld, int timelimit, const char *dn, const char *pw,
	 int with_sasl)
{
  int rc;
  int msgid;
  struct timeval tv;
  LDAPMessage *result;

  debug ("==> do_bind");

  /*
   * set timelimit in ld for select() call in ldap_pvt_connect() 
   * function implemented in libldap2's os-ip.c
   */
  tv.tv_sec = timelimit;
  tv.tv_usec = 0;

#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)
  if (!with_sasl)
    {
#endif
      msgid = ldap_simple_bind (ld, dn, pw);

      if (msgid < 0)
	{
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
	  if (ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &rc) !=
	      LDAP_SUCCESS)
	    {
	      rc = LDAP_UNAVAILABLE;
	    }
#else
	  rc = ld->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */
	  debug ("<== do_bind");

	  return rc;
	}

      rc = ldap_result (ld, msgid, 0, &tv, &result);
      if (rc > 0)
	{
	  debug ("<== do_bind");
	  return ldap_result2error (ld, result, 1);
	}

      /* took too long */
      if (rc == 0)
	{
	  ldap_abandon (ld, msgid);
	}
#if (defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))) || defined(HAVE_LDAP_GSS_BIND)
    }
  else
    {
#ifdef HAVE_LDAP_GSS_BIND
      return ldap_gss_bind (ld, dn, pw, GSSSASL_NO_SECURITY_LAYER,
			    LDAP_SASL_GSSAPI);
#else
# ifdef CONFIGURE_KRB5_CCNAME
      char tmpbuf[256];
      static char envbuf[256];
# endif	/* CONFIGURE_KRB5_CCNAME */

      if (__config->ldc_sasl_secprops != NULL)
	{
	  rc =
	    ldap_set_option (ld, LDAP_OPT_X_SASL_SECPROPS,
			     (void *) __config->ldc_sasl_secprops);
	  if (rc != LDAP_SUCCESS)
	    {
	      debug ("do_bind: unable to set SASL security properties");
	      return rc;
	    }
	}

# ifdef CONFIGURE_KRB5_CCNAME
      /* Set default Kerberos ticket cache for SASL-GSSAPI */
      /* There are probably race conditions here XXX */
      if (__config->ldc_krb5_ccname != NULL)
	{
	  char *oldccname;

	  oldccname = getenv ("KRB5CCNAME");
	  if (oldccname != NULL)
	    {
	      strncpy (tmpbuf, oldccname, sizeof (tmpbuf));
	      tmpbuf[sizeof (tmpbuf) - 1] = '\0';
	    }
	  else
	    {
	      tmpbuf[0] = '\0';
	    }
	  snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s",
		    __config->ldc_krb5_ccname);
	  putenv (envbuf);
	}
# endif	/* CONFIGURE_KRB5_CCNAME */

      rc = ldap_sasl_interactive_bind_s (ld, dn, "GSSAPI", NULL, NULL,
					 LDAP_SASL_QUIET,
					 do_sasl_interact, (void *)pw);

# ifdef CONFIGURE_KRB5_CCNAME
      /* Restore default Kerberos ticket cache. */
      if (__config->ldc_krb5_ccname != NULL)
	{
	  snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", tmpbuf);
	  putenv (envbuf);
	}
# endif	/* CONFIGURE_KRB5_CCNAME */

      return rc;
#endif /* HAVE_LDAP_GSS_BIND */
    }
#endif

  debug ("<== do_bind");

  return -1;
}

/*
 * This function initializes an enumeration context.
 * It is called from setXXent() directly, and so can safely lock the
 * mutex. 
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
ent_context_t *
_nss_ldap_ent_context_init (ent_context_t ** pctx)
{
  ent_context_t *ctx;

  debug ("==> _nss_ldap_ent_context_init");

  _nss_ldap_enter ();

  ctx = *pctx;

  if (ctx == NULL)
    {
      ctx = (ent_context_t *) malloc (sizeof (*ctx));
      if (ctx == NULL)
	{
	  _nss_ldap_leave ();
	  debug ("<== _nss_ldap_ent_context_init");
	  return NULL;
	}
      *pctx = ctx;
    }
  else
    {
      if (ctx->ec_res != NULL)
	{
	  ldap_msgfree (ctx->ec_res);
	}
#ifdef PAGE_RESULTS
      if (ctx->ec_cookie != NULL)
	{
	  ber_bvfree (ctx->ec_cookie);
	}
#endif /* PAGE_RESULTS */
      if (ctx->ec_msgid > -1 && _nss_ldap_result (ctx) == NSS_SUCCESS)
	{
	  ldap_abandon (__session.ls_conn, ctx->ec_msgid);
	}
    }

#ifdef PAGE_RESULTS
  ctx->ec_cookie = NULL;
#endif /* PAGE_RESULTS */
  ctx->ec_res = NULL;
  ctx->ec_msgid = -1;
  ctx->ec_sd = NULL;

  LS_INIT (ctx->ec_state);

  _nss_ldap_leave ();

  debug ("<== _nss_ldap_ent_context_init");
  return ctx;
}

/*
 * Clears a given context; we require the caller
 * to acquire the lock.
 */
void
_nss_ldap_ent_context_release (ent_context_t * ctx)
{
  debug ("==> _nss_ldap_ent_context_release");

  if (ctx == NULL)
    {
      debug ("<== _nss_ldap_ent_context_release");
      return;
    }

  if (ctx->ec_res != NULL)
    {
      ldap_msgfree (ctx->ec_res);
      ctx->ec_res = NULL;
    }
#ifdef PAGE_RESULTS
  if (ctx->ec_cookie != NULL)
    {
      ber_bvfree (ctx->ec_cookie);
      ctx->ec_cookie = NULL;
    }
#endif /* PAGE_RESULTS */

  /*
   * Abandon the search if there were more results to fetch.
   */
  if (ctx->ec_msgid > -1 && _nss_ldap_result (ctx) == NSS_SUCCESS)
    {
      ldap_abandon (__session.ls_conn, ctx->ec_msgid);
      ctx->ec_msgid = -1;
    }

  ctx->ec_sd = NULL;

  LS_INIT (ctx->ec_state);

  debug ("<== _nss_ldap_ent_context_release");

  return;
}

/*
 * Do the necessary formatting to create a string filter.
 */
static NSS_STATUS
do_filter (const ldap_args_t * args, const char *filterprot,
	   ldap_service_search_descriptor_t * sd, char *userbuf,
	   size_t userbufSiz, const char **retFilter)
{
  char buf1[LDAP_FILT_MAXSIZ], buf2[LDAP_FILT_MAXSIZ];
  char *filterBufP, filterBuf[LDAP_FILT_MAXSIZ];
  size_t filterSiz;
  NSS_STATUS stat;

  debug ("==> do_filter");

  if (args != NULL)
    {
      /* choose what to use for temporary storage */

      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  filterBufP = filterBuf;
	  filterSiz = sizeof (filterBuf);
	}
      else
	{
	  filterBufP = userbuf;
	  filterSiz = userbufSiz;
	}

      switch (args->la_type)
	{
	case LA_TYPE_STRING:
	  if ((stat =
	       _nss_ldap_escape_string (args->la_arg1.la_string, buf1,
					sizeof (buf1))) != NSS_SUCCESS)
	    return stat;
	  snprintf (filterBufP, filterSiz, filterprot, buf1);
	  break;
	case LA_TYPE_NUMBER:
	  snprintf (filterBufP, filterSiz, filterprot,
		    args->la_arg1.la_number);
	  break;
	case LA_TYPE_STRING_AND_STRING:
	  if ((stat =
	       _nss_ldap_escape_string (args->la_arg1.la_string, buf1,
					sizeof (buf1))) != NSS_SUCCESS
	      || (stat =
		  _nss_ldap_escape_string (args->la_arg2.la_string, buf2,
					   sizeof (buf2)) != NSS_SUCCESS))
	    return stat;
	  snprintf (filterBufP, filterSiz, filterprot, buf1, buf2);
	  break;
	case LA_TYPE_NUMBER_AND_STRING:
	  if ((stat =
	       _nss_ldap_escape_string (args->la_arg2.la_string, buf1,
					sizeof (buf1))) != NSS_SUCCESS)
	    return stat;
	  snprintf (filterBufP, filterSiz, filterprot,
		    args->la_arg1.la_number, buf1);
	  break;
	case LA_TYPE_STRING_UNESCAPED:
	  /* literal string */
	  snprintf (filterBufP, filterSiz, filterprot, args->la_arg1.la_string);
	  break;
	}

      /*
       * This code really needs to be cleaned up.
       */
      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  size_t filterBufPLen = strlen (filterBufP);

	  /* remove trailing bracket */
	  /* ( */
	  if (filterBufP[filterBufPLen - 1] == ')')
	    filterBufP[filterBufPLen - 1] = '\0';

	  /* ( */
	  snprintf (userbuf, userbufSiz, "%s(%s))",
		    filterBufP, sd->lsd_filter);
	}

      *retFilter = userbuf;
    }
  else
    {
      /* no arguments, probably an enumeration filter */
      if (sd != NULL && sd->lsd_filter != NULL)
	{
	  snprintf (userbuf, userbufSiz, "(&%s(%s))",
		    filterprot, sd->lsd_filter);
	  *retFilter = userbuf;
	}
      else
	{
	  *retFilter = filterprot;
	}
    }

  debug (":== do_filter: %s", *retFilter);

  debug ("<== do_filter");

  return NSS_SUCCESS;
}

/*
 * Wrapper around ldap_result() to skip over search references
 * and deal transparently with the last entry.
 */
static NSS_STATUS
do_result (ent_context_t * ctx, int all)
{
  int rc = LDAP_UNAVAILABLE;
  NSS_STATUS stat = NSS_TRYAGAIN;
  struct timeval tv, *tvp;

  debug ("==> do_result");

  if (__session.ls_config->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = __session.ls_config->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  do
    {
      rc =
	ldap_result (__session.ls_conn, ctx->ec_msgid, all, tvp,
		     &ctx->ec_res);
      switch (rc)
	{
	case -1:
	case 0:
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
	  if (ldap_get_option
	      (__session.ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
	    {
	      rc = LDAP_UNAVAILABLE;
	    }
#else
	  rc = __session.ls_conn->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */
	  syslog (LOG_ERR, "nss_ldap: could not get LDAP result - %s",
		  ldap_err2string (rc));
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
#ifdef PAGE_RESULTS
	      LDAPControl **resultControls = NULL;
#endif /* PAGE_RESULTS */

#ifdef PAGE_RESULTS
	      parserc =
		ldap_parse_result (__session.ls_conn, ctx->ec_res, &rc, NULL,
				   NULL, NULL, &resultControls, 1);
#else
	      parserc =
		ldap_parse_result (__session.ls_conn, ctx->ec_res, &rc, NULL,
				   NULL, NULL, NULL, 1);
#endif /* PAGE_RESULTS */
	      if (parserc != LDAP_SUCCESS
		  && parserc != LDAP_MORE_RESULTS_TO_RETURN)
		{
		  stat = NSS_UNAVAIL;
		  ldap_abandon (__session.ls_conn, ctx->ec_msgid);
		  syslog (LOG_ERR,
			  "nss_ldap: could not get LDAP result - %s",
			  ldap_err2string (rc));
		}
#ifdef PAGE_RESULTS
	      else if (resultControls != NULL)
		{
		  /* See if there are any more pages to come */
		  parserc = ldap_parse_page_control (__session.ls_conn,
						     resultControls, NULL,
						     &(ctx->ec_cookie));
		  ldap_controls_free (resultControls);
		  stat = NSS_NOTFOUND;
		}
#endif /* PAGE_RESULTS */
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
    time (&__session.ls_timestamp);

  debug ("<== do_result");

  return stat;
}

/*
 * Function to call either do_search() or do_search_s() with
 * reconnection logic.
 */
static NSS_STATUS
do_with_reconnect (const char *base, int scope,
		   const char *filter, const char **attrs, int sizelimit,
		   void *private, search_func_t search_func)
{
  int rc = LDAP_UNAVAILABLE, tries = 0, backoff = 0;
  int hard = 1;
  NSS_STATUS stat = NSS_TRYAGAIN;

  debug ("==> do_with_reconnect");

  while (stat == NSS_TRYAGAIN && hard &&
	 tries < LDAP_NSS_MAXCONNTRIES + LDAP_NSS_TRIES)
    {
      if (tries > LDAP_NSS_MAXCONNTRIES)
	{
	  if (backoff == 0)
	    backoff = LDAP_NSS_SLEEPTIME;
	  else if (backoff < LDAP_NSS_MAXSLEEPTIME)
	    backoff *= 2;

	  syslog (LOG_INFO,
		  "nss_ldap: reconnecting to LDAP server (sleeping %d seconds)...",
		  backoff);
	  (void) sleep (backoff);
	}
      else if (tries > 0)
	{
	  /* Don't sleep, reconnect immediately. */
	  syslog (LOG_INFO, "nss_ldap: reconnecting to LDAP server...");
	}

      if (do_open () != NSS_SUCCESS)
	{
	  __session.ls_conn = NULL;
	  /*
	   * If a soft reconnect policy is specified, then do not
	   * try to reconnect to the LDAP server if it is down.
	   */
	  if (__session.ls_config != NULL &&
	      __session.ls_config->ldc_reconnect_pol == LP_RECONNECT_SOFT)
	    hard = 0;

	  ++tries;
	  continue;
	}

      rc = search_func (base, scope, filter, attrs, sizelimit, private);

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
	  stat = NSS_NOTFOUND;
	  break;
	case LDAP_SERVER_DOWN:
	case LDAP_TIMEOUT:
	case LDAP_UNAVAILABLE:
	case LDAP_BUSY:
	case LDAP_LOCAL_ERROR:
#ifdef LDAP_CONNECT_ERROR
	case LDAP_CONNECT_ERROR:
#endif /* LDAP_CONNECT_ERROR */
	  do_close ();
	  stat = NSS_TRYAGAIN;
	  ++tries;
	  continue;
	  break;
	default:
	  stat = NSS_UNAVAIL;
	  break;
	}
    }

  switch (stat)
    {
    case NSS_UNAVAIL:
      syslog (LOG_ERR, "nss_ldap: could not search LDAP server - %s",
	      ldap_err2string (rc));
      break;
    case NSS_TRYAGAIN:
      syslog (LOG_ERR,
	      "nss_ldap: could not %s %sconnect to LDAP server - %s",
	      hard ? "hard" : "soft",
	      tries ? "re" : "", ldap_err2string (rc));
      stat = NSS_UNAVAIL;
      break;
    case NSS_SUCCESS:
      if (tries)
	{
	  syslog (LOG_INFO,
		  "nss_ldap: reconnected to LDAP server after %d attempt(s)",
		  tries);
	}
      time (&__session.ls_timestamp);
      break;
    default:
      break;
    }

  debug ("<== do_with_reconnect");
  return stat;
}

/*
 * Synchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search_s().
 */
static int
do_search_s (const char *base, int scope,
	     const char *filter, const char **attrs, int sizelimit,
	     LDAPMessage ** res)
{
  int rc;
  struct timeval tv, *tvp;

  debug ("==> do_search_s");

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_SIZELIMIT)
  ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
		   (void *) &sizelimit);
#else
  __session.ls_conn->ld_sizelimit = sizelimit;
#endif /* LDAP_OPT_SIZELIMIT */

  if (__session.ls_config->ldc_timelimit == LDAP_NO_LIMIT)
    {
      tvp = NULL;
    }
  else
    {
      tv.tv_sec = __session.ls_config->ldc_timelimit;
      tv.tv_usec = 0;
      tvp = &tv;
    }

  rc = ldap_search_st (__session.ls_conn, base, scope, filter,
		       (char **) attrs, 0, tvp, res);

  debug ("<== do_search_s");

  return rc;
}

/*
 * Asynchronous search function. Don't call this directly;
 * always wrap calls to this with do_with_reconnect(), or,
 * better still, use _nss_ldap_search().
 */
static int
do_search (const char *base, int scope,
	   const char *filter, const char **attrs, int sizelimit, int *msgid)
{
  int rc;
#ifdef PAGE_RESULTS
  LDAPControl *serverctrls[2] = { NULL, NULL };
#endif /* PAGE_RESULTS */
  debug ("==> do_search");

#ifdef PAGE_RESULTS
  rc = ldap_create_page_control (__session.ls_conn, LDAP_PAGESIZE, NULL, 0,
				 &serverctrls[0]);
  if (rc != LDAP_SUCCESS)
    return rc;
  rc = ldap_search_ext (__session.ls_conn, base, scope, filter,
			(char **) attrs, 0, serverctrls, NULL, LDAP_NO_LIMIT,
			sizelimit, msgid);
  ldap_control_free (serverctrls[0]);
#else
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_SIZELIMIT)
  ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
		   (void *) &sizelimit);
#else
  __session.ls_conn->ld_sizelimit = sizelimit;
#endif /* LDAP_OPT_SIZELIMIT */

  *msgid = ldap_search (__session.ls_conn, base, scope, filter,
			(char **) attrs, 0);
  if (*msgid < 0)
    {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
      if (ldap_get_option
	  (__session.ls_conn, LDAP_OPT_ERROR_NUMBER, &rc) != LDAP_SUCCESS)
	{
	  rc = LDAP_UNAVAILABLE;
	}
#else
      rc = __session.ls_conn->ld_errno;
#endif /* LDAP_OPT_ERROR_NUMBER */
    }
  else
    {
      rc = LDAP_SUCCESS;
    }
#endif /* PAGE_RESULTS */

  debug ("<== do_search");

  return rc;
}

/*
 * Tries parser function "parser" on entries, calling do_result()
 * to retrieve them from the LDAP server until one parses
 * correctly or there is an exceptional condition.
 */
static NSS_STATUS
do_parse (ent_context_t * ctx, void *result, char *buffer, size_t buflen,
	  int *errnop, parser_t parser)
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
	  resultStat = do_result (ctx, LDAP_MSG_ONE);
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
       * find one which is parseable, or exhaust avialable
       * entries, whichever is first.
       */
      parseStat =
	parser (__session.ls_conn, ctx->ec_res, &ctx->ec_state, result,
		buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_TRYAGAIN ? 1 : 0);

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

  *errnop = 0;
  if (parseStat == NSS_TRYAGAIN)
    {
#ifdef HAVE_NSSWITCH_H
      errno = ERANGE;
      *errnop = 1;		/* this is really erange */
#else
      *errnop = ERANGE;
#endif /* HAVE_NSSWITCH_H */
    }

  debug ("<== do_parse");

  return parseStat;
}

/*
 * Parse, fetching reuslts from chain instead of server.
 */
static NSS_STATUS
do_parse_s (ent_context_t * ctx, void *result, char *buffer, size_t buflen,
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
	    e = ldap_first_entry (__session.ls_conn, ctx->ec_res);
	  else
	    e = ldap_next_entry (__session.ls_conn, e);
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
       * find one which is parseable, or exhaust avialable
       * entries, whichever is first.
       */
      parseStat =
	parser (__session.ls_conn, e, &ctx->ec_state, result, buffer, buflen);

      /* hold onto the state if we're out of memory XXX */
      ctx->ec_state.ls_retry = (parseStat == NSS_TRYAGAIN ? 1 : 0);
    }
  while (parseStat == NSS_NOTFOUND);

  *errnop = 0;
  if (parseStat == NSS_TRYAGAIN)
    {
#ifdef HAVE_NSSWITCH_H
      errno = ERANGE;
      *errnop = 1;		/* this is really erange */
#else
      *errnop = ERANGE;
#endif /* HAVE_NSSWITCH_H */
    }

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
  return do_with_reconnect (dn, LDAP_SCOPE_BASE, "(objectclass=*)", attributes, 1,	/* sizelimit */
			    res, (search_func_t) do_search_s);
}

/*
 * Simple wrapper around ldap_get_values(). Requires that
 * session is already established.
 */
char **
_nss_ldap_get_values (LDAPMessage * e, const char *attr)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_get_values (__session.ls_conn, e, (char *) attr);
}

/*
 * Simple wrapper around ldap_get_dn(). Requires that
 * session is already established.
 */
char *
_nss_ldap_get_dn (LDAPMessage * e)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_get_dn (__session.ls_conn, e);
}

/*
 * Simple wrapper around ldap_first_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_first_entry (LDAPMessage * res)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_first_entry (__session.ls_conn, res);
}

/*
 * Simple wrapper around ldap_next_entry(). Requires that
 * session is already established.
 */
LDAPMessage *
_nss_ldap_next_entry (LDAPMessage * res)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_next_entry (__session.ls_conn, res);
}

/*
 * Calls ldap_result() with LDAP_MSG_ONE.
 */
NSS_STATUS
_nss_ldap_result (ent_context_t * ctx)
{
  if (__session.ls_conn == NULL)
    {
      return NSS_UNAVAIL;
    }
  return do_result (ctx, LDAP_MSG_ONE);
}

/*
 * The generic synchronous lookup cover function. 
 * Assumes caller holds lock.
 */
NSS_STATUS
_nss_ldap_search_s (const ldap_args_t * args,
		    const char *filterprot,
		    ldap_map_selector_t sel,
		    int sizelimit, LDAPMessage ** res)
{
  char sdBase[LDAP_FILT_MAXSIZ], *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ];
  const char **attrs, *filter;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;

  debug ("==> _nss_ldap_search_s");

  stat = do_open ();
  if (stat != NSS_SUCCESS)
    {
      __session.ls_conn = NULL;
      debug ("<== _nss_ldap_search_s");
      return stat;
    }

  /* Set some reasonable defaults. */
  base = __session.ls_config->ldc_base;
  scope = __session.ls_config->ldc_scope;
  attrs = NULL;

  if (sel < LM_NONE)
    {
      sd = __session.ls_config->ldc_sds[sel];
    next:if (sd != NULL)
	{
	  size_t len = strlen (sd->lsd_base);
	  if (sd->lsd_base[len - 1] == ',')
	    {
	      /* is relative */
	      snprintf (sdBase, sizeof (sdBase), "%s%s", sd->lsd_base,
			__session.ls_config->ldc_base);
	      base = sdBase;
	    }
	  else
	    {
	      base = sd->lsd_base;
	    }

	  if (sd->lsd_scope != -1)
	    {
	      scope = sd->lsd_scope;
	    }
	}
      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf), &filter);
  if (stat != NSS_SUCCESS)
    return stat;

  stat = do_with_reconnect (base, scope, filter,
			    attrs, sizelimit, res,
			    (search_func_t) do_search_s);

  /* if we got no entry, try the next base */
  if (stat == NSS_SUCCESS && sd && sd->lsd_next &&
      (ldap_first_entry (__session.ls_conn, *res) == NULL))
    {
      sd = sd->lsd_next;
      if (sd)
	goto next;
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
		  const char *filterprot,
		  ldap_map_selector_t sel, int sizelimit, int *msgid,
		  ldap_service_search_descriptor_t ** csd)
{
  char sdBase[LDAP_FILT_MAXSIZ], *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ];
  const char **attrs, *filter;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;

  debug ("==> _nss_ldap_search");

  *msgid = -1;

  stat = do_open ();
  if (stat != NSS_SUCCESS)
    {
      __session.ls_conn = NULL;
      debug ("<== _nss_ldap_search");
      return stat;
    }

  /* Set some reasonable defaults. */
  base = __session.ls_config->ldc_base;
  scope = __session.ls_config->ldc_scope;
  attrs = NULL;

  if (sel < LM_NONE || *csd != NULL)
    {
      /* If we were chasing multiple descriptors and there are none left,
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
	  sd = __session.ls_config->ldc_sds[sel];
	}

      *csd = sd;

      if (sd != NULL)
	{
	  size_t len = strlen (sd->lsd_base);
	  if (sd->lsd_base[len - 1] == ',')
	    {
	      /* is relative */
	      snprintf (sdBase, sizeof (sdBase), "%s%s", sd->lsd_base,
			__session.ls_config->ldc_base);
	      base = sdBase;
	    }
	  else
	    {
	      base = sd->lsd_base;
	    }

	  if (sd->lsd_scope != -1)
	    {
	      scope = sd->lsd_scope;
	    }
	}
      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf), &filter);
  if (stat != NSS_SUCCESS)
    return stat;

  stat = do_with_reconnect (base, scope, filter,
			    attrs, sizelimit, msgid,
			    (search_func_t) do_search);

  debug ("<== _nss_ldap_search");

  return stat;
}

#ifdef PAGE_RESULTS
static NSS_STATUS
do_next_page (const ldap_args_t * args,
	      const char *filterprot,
	      ldap_map_selector_t sel,
	      int sizelimit, int *msgid, struct berval *pCookie)
{
  char sdBase[LDAP_FILT_MAXSIZ], *base = NULL;
  char filterBuf[LDAP_FILT_MAXSIZ];
  const char **attrs, *filter;
  int scope;
  NSS_STATUS stat;
  ldap_service_search_descriptor_t *sd = NULL;
  LDAPControl *serverctrls[2] = { NULL, NULL };

  _nss_ldap_enter ();

  /* Set some reasonable defaults. */
  base = __session.ls_config->ldc_base;
  scope = __session.ls_config->ldc_scope;
  attrs = NULL;

  if (sel < LM_NONE)
    {
      sd = __session.ls_config->ldc_sds[sel];
      if (sd != NULL)
	{
	  size_t len = strlen (sd->lsd_base);
	  if (sd->lsd_base[len - 1] == ',')
	    {
	      /* is relative */
	      snprintf (sdBase, sizeof (sdBase), "%s%s", sd->lsd_base,
			__session.ls_config->ldc_base);
	      base = sdBase;
	    }
	  else
	    {
	      base = sd->lsd_base;
	    }

	  if (sd->lsd_scope != -1)
	    {
	      scope = sd->lsd_scope;
	    }
	}
      attrs = __session.ls_config->ldc_attrtab[sel];
    }

  stat =
    do_filter (args, filterprot, sd, filterBuf, sizeof (filterBuf), &filter);
  if (stat != NSS_SUCCESS)
    {
      _nss_ldap_leave ();
      return stat;
    }

  stat =
    ldap_create_page_control (__session.ls_conn, LDAP_PAGESIZE, pCookie, 0,
			      &serverctrls[0]);
  if (stat != LDAP_SUCCESS)
    {
      _nss_ldap_leave ();
      return NSS_UNAVAIL;
    }

  stat =
    ldap_search_ext (__session.ls_conn, base, __session.ls_config->ldc_scope,
		     (args == NULL) ? (char *) filterprot : filter,
		     (char **) attrs, 0, serverctrls, NULL, LDAP_NO_LIMIT,
		     sizelimit, msgid);
  ldap_control_free (serverctrls[0]);

  _nss_ldap_leave ();
  return (*msgid < 0) ? NSS_UNAVAIL : NSS_SUCCESS;
}
#endif /* PAGE_RESULTS */

/*
 * General entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 * Locks mutex.
 */
NSS_STATUS
_nss_ldap_getent (ent_context_t ** ctx,
		  void *result,
		  char *buffer,
		  size_t buflen,
		  int *errnop,
		  const char *filterprot,
		  ldap_map_selector_t sel, parser_t parser)
{
  NSS_STATUS stat = NSS_SUCCESS;

  debug ("==> _nss_ldap_getent");

  if (*ctx == NULL || (*ctx)->ec_msgid == -1)
    {
      /*
       * implicitly call setent() if this is the first time
       * or there is no active search
       */
      if (_nss_ldap_ent_context_init (ctx) == NULL)
	{
	  debug ("<== _nss_ldap_getent");
	  return NSS_UNAVAIL;
	}
    }

  /*
   * we need to lock here as the context may not be thread-specific
   * data (under glibc, for example). Maybe we should make the lock part
   * of the context.
   */

next:
  _nss_ldap_enter ();

  /*
   * If ctx->ec_msgid < 0, then we haven't searched yet. Let's do it!
   */
  if ((*ctx)->ec_msgid < 0)
    {
      int msgid;

      stat = _nss_ldap_search (NULL, filterprot, sel, LDAP_NO_LIMIT, &msgid,
			       &(*ctx)->ec_sd);
      if (stat != NSS_SUCCESS)
	{
	  _nss_ldap_leave ();
	  debug ("<== _nss_ldap_getent");
	  return stat;
	}

      (*ctx)->ec_msgid = msgid;
    }


  _nss_ldap_leave ();

  stat = do_parse (*ctx, result, buffer, buflen, errnop, parser);

#ifdef PAGE_RESULTS
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
	      debug ("<== _nss_ldap_getent");
	      return stat;
	    }
	  (*ctx)->ec_msgid = msgid;
	  stat = do_parse (*ctx, result, buffer, buflen, errnop, parser);
	}
    }
#endif /* PAGE_RESULTS */

  if (stat == NSS_NOTFOUND && (*ctx)->ec_sd)
    {
      (*ctx)->ec_msgid = -1;
      goto next;
    }

  debug ("<== _nss_ldap_getent");

  return stat;
}

/*
 * General match function.
 * Locks mutex.
 */
NSS_STATUS
_nss_ldap_getbyname (ldap_args_t * args,
		     void *result,
		     char *buffer,
		     size_t buflen,
		     int *errnop,
		     const char *filterprot,
		     ldap_map_selector_t sel, parser_t parser)
{
  NSS_STATUS stat = NSS_NOTFOUND;
  ent_context_t ctx;

  _nss_ldap_enter ();

  debug ("==> _nss_ldap_getbyname");

  ctx.ec_msgid = -1;
#ifdef PAGE_RESULTS
  ctx.ec_cookie = NULL;
#endif /* PAGE_RESULTS */

  stat = _nss_ldap_search_s (args, filterprot, sel, 1, &ctx.ec_res);
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

  stat = do_parse_s (&ctx, result, buffer, buflen, errnop, parser);

  _nss_ldap_ent_context_release (&ctx);

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
_nss_ldap_assign_attrvals (LDAP * ld,
			   LDAPMessage * e,
			   const char *attr,
			   const char *omitvalue,
			   char ***valptr,
			   char **pbuffer,
			   size_t * pbuflen, size_t * pvalcount)
{
  char **vals;
  char **valiter;
  int valcount;
  char **p = NULL;

  register int buflen = *pbuflen;
  register char *buffer = *pbuffer;

  if (pvalcount != NULL)
    {
      *pvalcount = 0;
    }

  vals = ldap_get_values (ld, e, (char *) attr);

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
_nss_ldap_assign_attrval (LDAP * ld,
			  LDAPMessage * e,
			  const char *attr,
			  char **valptr, char **buffer, size_t * buflen)
{
  char **vals;
  int vallen;
#ifdef AT_OC_MAP
  const char *ovr, *def;

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
#endif /* AT_OC_MAP */

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals == NULL)
#ifdef AT_OC_MAP
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
#else
    return NSS_NOTFOUND;
#endif /* AT_OC_MAP */

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

/*
 * Assign a single value to *valptr, after examining userPassword for
 * a syntactically suitable value. 
 */
NSS_STATUS
_nss_ldap_assign_userpassword (LDAP * ld,
			       LDAPMessage * e,
			       const char *attr,
			       char **valptr, char **buffer, size_t * buflen)
{
  char **vals;
  char **valiter;
  char *pwd = NULL;
  int vallen;
#ifndef AT_OC_MAP
  static char *__crypt_token = "{CRYPT}";
  static size_t __crypt_token_length = sizeof ("{CRYPT}") - 1;
#endif /* AT_OC_MAP */
  const char *token = NULL;
  size_t token_length = 0;

  debug ("==> _nss_ldap_assign_userpassword");
#ifdef AT_OC_MAP
  if (__config != NULL)
    {
      switch (__config->ldc_password_type)
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
#else
  token = __crypt_token;
  token_length = __crypt_token_length;
#endif /* AT_OC_MAP */

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals != NULL)
    {
      for (valiter = vals; *valiter != NULL; valiter++)
	{
#ifdef AT_OC_MAP
	  if (token_length == 0 ||
	      strncasecmp (*valiter, token, token_length) == 0)
#else
	  if (strncasecmp (*valiter, token, token_length) == 0)
#endif /* AT_OC_MAP */
	    {
	      pwd = *valiter;
	      break;
	    }
	}
    }

  if (pwd == NULL)
    {
      pwd = "x";
    }
  else
    {
      pwd += token_length;
    }

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
_nss_ldap_oc_check (LDAP * ld, LDAPMessage * e, const char *oc)
{
  char **vals, **valiter;
  NSS_STATUS ret = NSS_NOTFOUND;

  vals = ldap_get_values (ld, e, "objectClass");
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

#ifdef AT_OC_MAP

#ifdef HAVE_SHADOW_H
int
_nss_ldap_shadow_date (const char *val)
{
  int date;

  if (__config->ldc_shadow_type == LS_AD_SHADOW)
    {
      date = atoll (val) / 864000000000LL - 134774LL;
      date = (date > 99999) ? 99999 : date;
    }
  else
    {
      date = atol (val);
    }
  return date;
}

void
_nss_ldap_shadow_handle_flag (struct spwd *sp)
{
  if (__config->ldc_shadow_type == LS_AD_SHADOW)
    {
      if (sp->sp_flag & UF_DONT_EXPIRE_PASSWD)
	sp->sp_max = 99999;
      sp->sp_flag = 0;
    }
}
#endif /* HAVE_SHADOW_H */

const char *
_nss_ldap_map_at (const char *attribute)
{
  char *mapped;

  if (_nss_ldap_atmap_get (__config, attribute, (const char **) &mapped) ==
      NSS_NOTFOUND)
    return attribute;

  return mapped;
}

const char *
_nss_ldap_map_oc (const char *objectclass)
{
  char *mapped;

  if (_nss_ldap_ocmap_get (__config, objectclass, (const char **) &mapped) ==
      NSS_NOTFOUND)
    return objectclass;

  return mapped;
}

const char *
_nss_ldap_map_ov (const char *attribute)
{
  char *value;

  if (_nss_ldap_ovmap_get (__config, attribute, (const char **) &value) ==
      NSS_NOTFOUND)
    return NULL;

  return value;
}

const char *
_nss_ldap_map_df (const char *attribute)
{
  char *value;

  if (_nss_ldap_dfmap_get (__config, attribute, (const char **) &value) ==
      NSS_NOTFOUND)
    return NULL;

  return value;
}

NSS_STATUS
_nss_ldap_map_put (ldap_config_t * config, ldap_map_type_t type,
		   const char *rfc2307attribute, const char *value)
{
  DBT key, val;
  int rc;
  char *vadup;
  void **map;

  switch (type)
    {
    case MAP_ATTRIBUTE:
      /* special handling for attribute mapping */
      if (strcmp (rfc2307attribute, "userPassword") == 0)
	{
	  if (strcasecmp (value, "userPassword") == 0)
	    config->ldc_password_type = LU_RFC2307_USERPASSWORD;
	  else if (strcasecmp (value, "authPassword") == 0)
	    config->ldc_password_type = LU_RFC3112_AUTHPASSWORD;
	  else
	    config->ldc_password_type = LU_OTHER_PASSWORD;
	}
      else if (strcmp (rfc2307attribute, "shadowLastChange") == 0)
	{
	  if (strcasecmp (value, "shadowLastChange") == 0)
	    config->ldc_shadow_type = LS_RFC2307_SHADOW;
	  else if (strcasecmp (value, "pwdLastSet") == 0)
	    config->ldc_shadow_type = LS_AD_SHADOW;
	  else
	    config->ldc_shadow_type = LS_OTHER_SHADOW;
	}
      break;
    case MAP_OBJECTCLASS:
    case MAP_OVERRIDE:
    case MAP_DEFAULT:
      break;
    default:
      return NSS_NOTFOUND;
      break;
    }

  map = &config->ldc_maps[type];
  assert(*map != NULL);

  vadup = strdup (value);
  if (vadup == NULL)
    return NSS_TRYAGAIN;

  memset (&key, 0, sizeof(key));
  key.data = (void *) rfc2307attribute;
  key.size = strlen (rfc2307attribute);

  memset (&val, 0, sizeof(val));
  val.data = (void *) &vadup;
  val.size = sizeof (vadup);

  rc = (((DB *) (*map))->put) ((DB *) * map,
#if DB_VERSION_MAJOR > 2
			       NULL,	/* DB_TXN */
#endif /* DB_VERSION_MAJOR */
			       &key, &val, 0);

  return (rc != 0) ? NSS_TRYAGAIN : NSS_SUCCESS;
}

NSS_STATUS
_nss_ldap_atmap_get (ldap_config_t * config,
		     const char *rfc2307attribute, const char **attribute)
{
  NSS_STATUS stat;

  stat =
    _nss_ldap_map_get (config, MAP_ATTRIBUTE, rfc2307attribute, attribute);
  if (stat == NSS_NOTFOUND)
    {
      *attribute = rfc2307attribute;
    }
  return stat;
}

NSS_STATUS
_nss_ldap_ocmap_get (ldap_config_t * config,
		     const char *rfc2307objectclass, const char **objectclass)
{
  NSS_STATUS stat;

  stat =
    _nss_ldap_map_get (config, MAP_OBJECTCLASS, rfc2307objectclass,
		       objectclass);
  if (stat == NSS_NOTFOUND)
    {
      *objectclass = rfc2307objectclass;
    }
  return stat;
}

NSS_STATUS
_nss_ldap_ovmap_get (ldap_config_t * config,
		     const char *rfc2307attribute, const char **value)
{
  NSS_STATUS stat;

  stat = _nss_ldap_map_get (config, MAP_OVERRIDE, rfc2307attribute, value);
  if (stat == NSS_NOTFOUND)
    {
      *value = NULL;
    }
  return stat;
}

NSS_STATUS
_nss_ldap_dfmap_get (ldap_config_t * config,
		     const char *rfc2307attribute, const char **value)
{
  NSS_STATUS stat;

  stat = _nss_ldap_map_get (config, MAP_DEFAULT, rfc2307attribute, value);
  if (stat == NSS_NOTFOUND)
    {
      *value = NULL;
    }
  return stat;
}

NSS_STATUS
_nss_ldap_map_get (ldap_config_t * config, ldap_map_type_t type,
		   const char *rfc2307attribute, const char **value)
{
  DBT key, val;
  void *map;

  if (config == NULL || type > MAP_MAX)
    {
      return NSS_NOTFOUND;
    }

  map = config->ldc_maps[type];
  assert(map != NULL);

  memset (&key, 0, sizeof(key));
  key.data = (void *) rfc2307attribute;
  key.size = strlen (rfc2307attribute);

  memset (&val, 0, sizeof(val));

  if ((((DB *) map)->get) ((DB *) map,
#if DB_VERSION_MAJOR > 2
			   NULL,
#endif
			   &key, &val, 0) != 0)
    {
      return NSS_NOTFOUND;
    }

  *value = *((char **) val.data);

  return NSS_SUCCESS;
}
#endif /* AT_OC_MAP */

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
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_proxy_bind_args_t *who = (ldap_proxy_bind_args_t *) arg;
#else
  ldap_proxy_bind_args_t *who = &__proxy_args;
#endif

  timelimit = __session.ls_config->ldc_bind_timelimit;

  return do_bind (ld, timelimit, who->binddn, who->bindpw, 0);
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
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_proxy_bind_args_t *who = (ldap_proxy_bind_args_t *) arg;
#else
  ldap_proxy_bind_args_t *who = &__proxy_args;
#endif
  if (freeit)
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
			     LM_PASSWD, 1, &res);
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
	      ldap_set_rebind_proc (__session.ls_conn, do_proxy_rebind, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
	      ldap_set_rebind_proc (__session.ls_conn, do_proxy_rebind);
#endif

	      debug (":== _nss_ldap_proxy_bind: %s", proxy_args->binddn);

	      rc = do_bind (__session.ls_conn,
			    __session.ls_config->ldc_bind_timelimit,
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
	      do_close ();
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

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && (defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H))
static int
do_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *_interact)
{
  char *authzid = (char *)defaults;
  sasl_interact_t *interact = (sasl_interact_t *) _interact;

  while (interact->id != SASL_CB_LIST_END)
    {
      if (interact->id == SASL_CB_USER)
	{
	  if (authzid != NULL)
	    {
		interact->result = authzid;
		interact->len = strlen(authzid);
	    }
	  else if (interact->defresult != NULL)
	    {
		interact->result = interact->defresult;
		interact->len = strlen(interact->defresult);
	    }
	  else
	   {
		interact->result = "";
		interact->len = 0;
	   }
	}
      else
	{
	  return LDAP_PARAM_ERROR;
	}
      interact++;
    }
  return LDAP_SUCCESS;
}
#endif

/* #include "sldap-compat.c" */

