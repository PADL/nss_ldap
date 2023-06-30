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

   $Id$
 */

#ifndef _LDAP_NSS_LDAP_LDAP_NSS_H
#define _LDAP_NSS_LDAP_LDAP_NSS_H

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

/* for glibc, use weak aliases to pthreads functions */
#ifdef HAVE_LIBC_LOCK_H
#include <libc-lock.h>
#elif defined(HAVE_BITS_LIBC_LOCK_H)
#include <bits/libc-lock.h>
#endif

#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#ifndef __P
# if defined(__STDC__) || defined(__GNUC__)
#  define __P(x) x
# else
#  define __P(x) ()
# endif
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>

#ifdef HAVE_NSSWITCH_H
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#elif defined(HAVE_NSS_H)
#include <nss.h>
#elif defined(HAVE_IRS_H)
#include "irs-nss.h"
#endif

#include "ldap-schema.h"

#ifndef NSS_BUFSIZ
#define NSS_BUFSIZ	      1024
#endif

#ifndef NSS_BUFLEN_GROUP
#define NSS_BUFLEN_GROUP	LDAP_NSS_BUFLEN_GROUP
#endif

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD       NSS_BUFSIZ
#endif

#ifndef HAVE_NSSWITCH_H
#define NSS_BUFLEN_HOSTS	(NSS_BUFSIZ + (MAXALIASES + MAXALIASES + 2) * sizeof (char *))
#define NSS_BUFLEN_NETGROUP     (MAXHOSTNAMELEN * 2 + LOGNAME_MAX + 3)
#define NSS_BUFLEN_NETWORKS     NSS_BUFSIZ
#define NSS_BUFLEN_PROTOCOLS    NSS_BUFSIZ
#define NSS_BUFLEN_RPC	  NSS_BUFSIZ
#define NSS_BUFLEN_SERVICES     NSS_BUFSIZ
#define NSS_BUFLEN_SHADOW       NSS_BUFSIZ
#define NSS_BUFLEN_ETHERS       NSS_BUFSIZ
#define NSS_BUFLEN_BOOTPARAMS   NSS_BUFSIZ
#endif /* HAVE_NSSWITCH_H */

/*
 * Timeouts for reconnecting code. Similar to rebind
 * logic in Darwin NetInfo. Some may find sleeping
 * unacceptable, in which case you may wish to adjust
 * the constants below.
 */
#define LDAP_NSS_TRIES	   5	/* number of sleeping reconnect attempts */
#define LDAP_NSS_SLEEPTIME       4	/* seconds to sleep; doubled until max */
#define LDAP_NSS_MAXSLEEPTIME    64	/* maximum seconds to sleep */
#define LDAP_NSS_MAXCONNTRIES    2	/* reconnect attempts before sleeping */

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_IRS_H)
#define LDAP_NSS_MAXNETGR_DEPTH  16	/* maximum depth of netgroup nesting for innetgr() */
#endif /* HAVE_NSSWITCH_H */

#define LDAP_NSS_MAXGR_DEPTH     16     /* maximum depth of group nesting for getgrent()/initgroups() */

#if LDAP_NSS_NGROUPS > 64
#define LDAP_NSS_BUFLEN_GROUP	(NSS_BUFSIZ + (LDAP_NSS_NGROUPS * (sizeof (char *) + LOGNAME_MAX))) 
#else
#define LDAP_NSS_BUFLEN_GROUP	NSS_BUFSIZ
#endif /* LDAP_NSS_NGROUPS > 64 */

#define LDAP_NSS_BUFLEN_DEFAULT	0

#ifdef HAVE_USERSEC_H
#define LDAP_NSS_MAXUESS_ATTRS	8	/* maximum number of attributes in a getentry call */
#endif /* HAVE_USERSEC_H */

#define LDAP_PAGESIZE 1000

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* !LDAP_FILT_MAXSIZ */

#ifndef LDAPS_PORT
#define LDAPS_PORT 636
#endif /* !LDAPS_PORT */

#ifndef LOGNAME_MAX
#define LOGNAME_MAX 8
#endif /* LOGNAME_MAX */

#ifndef MAP_KEY_MAXSIZ
#define MAP_KEY_MAXSIZ 64
#endif

#ifdef DEBUG
#ifdef DEBUG_SYSLOG
#ifdef HAVE_NSSWITCH_H
#define debug(fmt, args...) syslog(LOG_DEBUG, "nss_ldap: %s:%d thread %u - " fmt, __FILE__, __LINE__, (uint)thr_self() , ## args)
#else
#define debug(fmt, args...) syslog(LOG_DEBUG, "nss_ldap: %s:%d thread %u - " fmt, __FILE__, __LINE__, (uint)pthread_self() , ## args)
#endif /* HAVE_NSSWITCH_H */
#else
#ifndef __GNUC__
#include <stdarg.h>
#include <stdio.h>
static void
debug (char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  fprintf (stderr, "nss_ldap: ");
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fprintf (stderr, "\n");
}
#else
#define debug(fmt, args...) fprintf(stderr, "nss_ldap: " fmt "\n" , ## args)
#endif /* __GNUC__ */
#endif /* DEBUG_SYSLOG */
#else
#ifndef __GNUC__
static void
debug (char *fmt, ...)
{
}
#else
#define debug(fmt, args...)
#endif /* __GNUC__ */
#endif /* DEBUG */

#ifdef __GNUC__
#define alignof(ptr) __alignof__(ptr)
#define INLINE inline
#elif defined(HAVE_ALIGNOF_H)
#include <alignof.h>
#define INLINE
#else
#define alignof(ptr) (sizeof(char *))
#define INLINE
#endif /* __GNUC__ */

#define align(ptr, blen, TYPE)	      do { \
					char *qtr = ptr; \
					ptr += alignof(TYPE) - 1; \
					ptr -= ((ptr - (char *)NULL) % alignof(TYPE)); \
					blen -= (ptr - qtr); \
				} while (0)

/* worst case */
#define bytesleft(ptr, blen, TYPE)    ( (blen < alignof(TYPE)) ? \
					    0 : (blen - alignof(TYPE) + 1))

/* selectors for different maps */
enum ldap_map_selector
{
  LM_PASSWD,
  LM_SHADOW,
  LM_GROUP,
  LM_HOSTS,
  LM_SERVICES,
  LM_NETWORKS,
  LM_PROTOCOLS,
  LM_RPC,
  LM_ETHERS,
  LM_NETMASKS,
  LM_BOOTPARAMS,
  LM_ALIASES,
  LM_NETGROUP,
  LM_AUTOMOUNT,
  LM_NONE
};

typedef enum ldap_map_selector ldap_map_selector_t;

enum ldap_userpassword_selector
{
  LU_RFC2307_USERPASSWORD,
  LU_RFC3112_AUTHPASSWORD,
  LU_OTHER_PASSWORD
};

typedef enum ldap_userpassword_selector ldap_userpassword_selector_t;

enum ldap_shadow_selector
{
  LS_RFC2307_SHADOW,
  LS_AD_SHADOW,
  LS_OTHER_SHADOW
};

typedef enum ldap_shadow_selector ldap_shadow_selector_t;

#ifndef UF_DONT_EXPIRE_PASSWD
#define UF_DONT_EXPIRE_PASSWD 0x10000
#endif

enum ldap_ssl_options
{
  SSL_OFF,
  SSL_LDAPS,
  SSL_START_TLS
};

typedef enum ldap_ssl_options ldap_ssl_options_t;

enum ldap_reconnect_policy
{
  LP_RECONNECT_HARD_INIT,
  LP_RECONNECT_HARD_OPEN,
  LP_RECONNECT_SOFT
};

typedef enum ldap_reconnect_policy ldap_reconnect_policy_t;

/*
 * POSIX profile information (not used yet)
 * see draft-joslin-config-schema-00.txt
 */
struct ldap_service_search_descriptor
{
  /* search base, qualified */
  char *lsd_base;
  /* scope */
  int lsd_scope;
  /* filter */
  char *lsd_filter;
  /* next */
  struct ldap_service_search_descriptor *lsd_next;
};

typedef struct ldap_service_search_descriptor
  ldap_service_search_descriptor_t;

/* maximum number of URIs */
#define NSS_LDAP_CONFIG_URI_MAX		31

/*
 * linked list of configurations pointing to LDAP servers. The first
 * which has a successful ldap_open() is used. Conceivably the rest
 * could be used after a failed or exhausted search.
 */
struct ldap_config
{
  /* Name of the file from which the config has been read */
  char *ldc_config_filename;
  /* NULL terminated list of URIs */
  char *ldc_uris[NSS_LDAP_CONFIG_URI_MAX + 1];
  /* default port, if not specified in URI */
  int ldc_port;
  /* base DN, eg. dc=gnu,dc=org */
  char *ldc_base;
  /* scope for searches */
  int ldc_scope;
  /* dereference aliases/links */
  int ldc_deref;
  /* bind DN */
  char *ldc_binddn;
  /* bind cred */
  char *ldc_bindpw;
  /* sasl auth id */
  char *ldc_saslid;
  /* do we use sasl when binding? */
  int ldc_usesasl;
  /* shadow bind DN */
  char *ldc_rootbinddn;
  /* shadow bind cred */
  char *ldc_rootbindpw;
  /* shadow sasl auth id */
  char *ldc_rootsaslid;
  /* do we use sasl for root? */
  int ldc_rootusesasl;
  /* protocol version */
  int ldc_version;
  /* search timelimit */
  int ldc_timelimit;
  /* bind timelimit */
  int ldc_bind_timelimit;
  /* SSL enabled */
  ldap_ssl_options_t ldc_ssl_on;
  /* SSL certificate path */
  char *ldc_sslpath;
  /* Chase referrals */
  int ldc_referrals;
  int ldc_restart;
  /* naming contexts */
  ldap_service_search_descriptor_t *ldc_sds[LM_NONE];
  /* tls check peer */
  int ldc_tls_checkpeer;
  /* tls ca certificate file */
  char *ldc_tls_cacertfile;
  /* tls ca certificate dir */
  char *ldc_tls_cacertdir;
  /* tls ciphersuite */
  char *ldc_tls_ciphers;
  /* tls certificate */
  char *ldc_tls_cert;
  /* tls key */
  char *ldc_tls_key;
  /* tls randfile */
  char *ldc_tls_randfile;
  /* idle timeout */
  time_t ldc_idle_timelimit;
  /* reconnect policy */
  ldap_reconnect_policy_t ldc_reconnect_pol;
  int ldc_reconnect_tries;
#define USECSPERSEC	1000000
  /* sleep time in microseconds */
  unsigned long ldc_reconnect_sleeptime;
  /* max sleep time in microseconds */
  unsigned long ldc_reconnect_maxsleeptime;
  int ldc_reconnect_maxconntries;

  /* sasl security */
  char *ldc_sasl_secprops;
  /* DNS SRV RR domain */
  char *ldc_srv_domain;
  /* DNS SRV RR site */
  char *ldc_srv_site;
  /* directory for debug files */
  char *ldc_logdir;
  /* LDAP debug level */
  int ldc_debug;
  int ldc_pagesize;
#if defined(CONFIGURE_KRB5_CCNAME) || defined(CONFIGURE_KRB5_KEYTAB)
  /* krb5 ccache name */
  char *ldc_krb5_ccname;
  char *ldc_krb5_rootccname;
  int ldc_krb5_autorenew;
  int ldc_krb5_rootautorenew;
#endif /* CONFIGURE_KRB5_CCNAME */
#ifdef CONFIGURE_KRB5_KEYTAB
  /* krb5 keytab name */
  char *ldc_krb5_keytabname;
  char *ldc_krb5_rootkeytabname;
  int ldc_krb5_usekeytab;
  int ldc_krb5_rootusekeytab;
#endif /* CONFIGURE_KRB5_KEYTAB */
  /*
   * attribute/objectclass maps relative to this config
   */
  void *ldc_maps[LM_NONE + 1][7]; /* must match MAP_MAX */

  /*
   * is userPassword "userPassword" or not? 
   * ie. do we need {crypt} to be stripped
   */
  ldap_userpassword_selector_t ldc_password_type;
  /*
   * Use active directory time offsets?
   */
  ldap_shadow_selector_t ldc_shadow_type;

  /* 
   * attribute table for ldap search requensts
   */
  const char **ldc_attrtab[LM_NONE + 1];

  unsigned int ldc_flags;

  /* last modification time */
  time_t ldc_mtime;

  char **ldc_initgroups_ignoreusers;
};

typedef struct ldap_config ldap_config_t;

#ifdef HAVE_SOCKLEN_T
typedef socklen_t NSS_LDAP_SOCKLEN_T;
#else
typedef int NSS_LDAP_SOCKLEN_T;
#endif /* HAVE_SOCKLEN_T */

#if defined(__GLIBC__) && __GLIBC_MINOR__ > 1
typedef struct sockaddr_storage NSS_LDAP_SOCKADDR_STORAGE;
#else
typedef struct sockaddr NSS_LDAP_SOCKADDR_STORAGE;
#define ss_family sa_family
#endif /* __GLIBC__ */

/*
 * Opaque structures are used by subsystems such as the Kerberos facilities
 */
enum ldap_session_opaque_type
{
  LSO_UNKNOWN = 0,
  LSO_KRB5
};

typedef enum ldap_session_opaque_type ldap_session_opaque_type_t;

struct ldap_session_opaque
{
  ldap_session_opaque_type_t lso_type;
  struct ldap_session_opaque *lso_next, *lso_prev;
  void *lso_data;
};

typedef struct ldap_session_opaque *ldap_session_opaque_t;

/*
 * Predeclare this as we use it in the ldap_session structure
 */
typedef struct ldap_session_mech *ldap_session_mech_t;

struct ldap_session_mechs
{
  int			lsms_count;
  ldap_session_mech_t	lsms_mechs[1];
};

typedef struct ldap_session_mechs *ldap_session_mechs_t;
/*
 * Session state management
 */
enum ldap_session_state
{
  LS_UNINITIALIZED = -1,
  LS_INITIALIZED,
  LS_CONNECTED_TO_DSA
};

typedef enum ldap_session_state ldap_session_state_t;

/*
 * convenient wrapper around pointer into global config list, and a
 * connection to an LDAP server.
 */
struct ldap_session
{
  /* the connection */
  LDAP *ls_conn;
  /* pointer into config table */
  ldap_config_t *ls_config;
  /* timestamp of last activity */
  time_t ls_timestamp;
  /* has session been connected? */
  ldap_session_state_t ls_state;
  /* index into ldc_uris: currently connected DSA */
  int ls_current_uri;
  /* Process id session was established under */
  pid_t pid;
  /* Effective UID session was established under */
  uid_t euid;
  /* Opaque structure pointer used by KRB5 routines */
  ldap_session_opaque_t ls_opaque;
  /* SASL mechanisms */
  ldap_session_mechs_t ls_mechs;
  /* These are large structures (128 bytes plus on Linux) */
  /* keep track of the LDAP sockets */
  NSS_LDAP_SOCKADDR_STORAGE ls_sockname;
  NSS_LDAP_SOCKADDR_STORAGE ls_peername;
};

typedef struct ldap_session ldap_session_t;

/*
 * SASL mechanisms are provided as plugins. this supports the vectors
 */

enum ldap_session_mech_type
{
  LSM_UNKNOWN = 0,
  LSM_KRB5,
  LSM_EXTERNAL
};

typedef enum ldap_session_mech_type ldap_session_mech_type_t;

typedef void * (*ldap_session_mech_init_t) (ldap_session_t *);
typedef int (*ldap_session_mech_select_t) (ldap_session_t *);
typedef int (*ldap_session_mech_restore_t) (ldap_session_t *);
typedef void (*ldap_session_mech_close_t) (ldap_session_t *);

struct ldap_session_mech
{
  ldap_session_mech_type_t	lsm_type;
  ldap_session_mech_init_t	lsm_init;
  ldap_session_mech_select_t	lsm_select;
  ldap_session_mech_restore_t	lsm_restore;
  ldap_session_mech_close_t	lsm_close;
};

typedef ldap_session_mech_t (*ldap_session_mech_setup_t)(void);

#ifndef HAVE_NSSWITCH_H
#ifndef UID_NOBODY
#define UID_NOBODY      (-2)
#endif
#endif

#ifndef GID_NOBODY
#define GID_NOBODY     UID_NOBODY
#endif

enum ldap_args_types
{
  LA_TYPE_STRING,
  LA_TYPE_NUMBER,
  LA_TYPE_STRING_AND_STRING,
  LA_TYPE_NUMBER_AND_STRING,
  LA_TYPE_TRIPLE,
  LA_TYPE_STRING_LIST_OR,
  LA_TYPE_STRING_LIST_AND,
  LA_TYPE_NONE
};

typedef enum ldap_args_types ldap_args_types_t;

enum ldap_map_type
{
  MAP_ATTRIBUTE = 0,
  MAP_OBJECTCLASS,
  MAP_OVERRIDE,
  MAP_DEFAULT,
  MAP_ATTRIBUTE_REVERSE,
  MAP_OBJECTCLASS_REVERSE, /* XXX not used yet? */
  MAP_MATCHING_RULE,
  MAP_MAX = MAP_MATCHING_RULE
};

typedef enum ldap_map_type ldap_map_type_t;

struct ldap_args
{
  ldap_args_types_t la_type;
  union
  {
    const char *la_string;
    long la_number;
    struct {
      /* for Solaris netgroup support */
      const char *host;
      const char *user;
      const char *domain;
    } la_triple;
    const char **la_string_list;
  }
  la_arg1;
  union
  {
    const char *la_string;
  }
  la_arg2;
  const char *la_base; /* override default base */
};

typedef struct ldap_args ldap_args_t;

#define LA_INIT(q)				do { \
						(q).la_type = LA_TYPE_STRING; \
						(q).la_arg1.la_string = NULL; \
						(q).la_arg2.la_string = NULL; \
						(q).la_base = NULL; \
						} while (0)
#define LA_TYPE(q)				((q).la_type)
#define LA_STRING(q)				((q).la_arg1.la_string)
#define LA_NUMBER(q)				((q).la_arg1.la_number)
#define LA_TRIPLE(q)				((q).la_arg1.la_triple)
#define LA_STRING_LIST(q)			((q).la_arg1.la_string_list)
#define LA_STRING2(q)				((q).la_arg2.la_string)
#define LA_BASE(q)				((q).la_base)

#include "ldap-parse.h"

/*
 * the state consists of the desired attribute value or an offset into a list of
 * values for the desired attribute. This is necessary to support services.
 *
 * Be aware of the arbitary distinction between state and context. Context is
 * the enumeration state of a lookup subsystem (which may be per-subsystem,
 * or per-subsystem/per-thread, depending on the OS). State is the state
 * of a particular lookup, and is only concerned with resolving and enumerating
 * services. State is represented as instances of ldap_state_t; context as
 * instances of ent_context_t. The latter contains the former.
 */
struct ldap_state
{
  int ls_type;
  int ls_retry;
  int ls_eof;
#define LS_TYPE_KEY	(0)
#define LS_TYPE_INDEX	(1)
  union
  {
    /* ls_key is the requested attribute value.
       ls_index is the desired offset into the value list.
     */
    const char *ls_key;
    int ls_index;
  }
  ls_info;
};

typedef struct ldap_state ldap_state_t;
/*
 * LS_INIT only used for enumeration contexts
 */
#define LS_INIT(state)	do { state.ls_type = LS_TYPE_INDEX; state.ls_retry = 0; state.ls_info.ls_index = -1; } while (0)

/*
 * thread specific context: result chain, and state data
 */
struct ent_context
{
  ldap_state_t ec_state;	/* eg. for services */
  int ec_msgid;			/* message ID */
  LDAPMessage *ec_res;		/* result chain */
  ldap_service_search_descriptor_t *ec_sd;	/* current sd */
  struct berval *ec_cookie;     /* cookie for paged searches */
  int ec_eof : 1;		/* reached notional end of file */
  int ec_internal : 1;		/* this context is just a part of a larger
				 * query for information */
};

typedef struct ent_context ent_context_t;

struct name_list
{
  char *name;
  struct name_list *next;
};

#ifdef HAVE_NSSWITCH_H

struct nss_ldap_backend
{
  nss_backend_op_t *ops;
  int n_ops;
  ent_context_t *state;
};

typedef struct nss_ldap_backend nss_ldap_backend_t;

struct nss_ldap_netgr_backend
{
  nss_backend_op_t *ops;
  int n_ops;
  ent_context_t *state;
  struct name_list *known_groups; /* netgroups seen, for loop detection */
  struct name_list *needed_groups; /* nested netgroups to chase */
};

typedef struct nss_ldap_netgr_backend nss_ldap_netgr_backend_t;

typedef nss_status_t NSS_STATUS;

#define NSS_RETURN		NSS_UNAVAIL

#elif defined(HAVE_IRS_H)

typedef enum
{
  NSS_TRYAGAIN = -2,
  NSS_UNAVAIL,
  NSS_NOTFOUND,
  NSS_SUCCESS,
  NSS_RETURN
}
NSS_STATUS;

struct nss_ldap_netgr_backend
{
  char buffer[NSS_BUFLEN_NETGROUP];
  ent_context_t *state;
  struct name_list *known_groups; /* netgroups seen, for loop detection */
  struct name_list *needed_groups; /* nested netgroups to chase */
};

typedef struct nss_ldap_netgr_backend nss_ldap_netgr_backend_t;
#elif defined(HAVE_NSS_H)

typedef enum nss_status NSS_STATUS;

#define NSS_SUCCESS		NSS_STATUS_SUCCESS
#define NSS_NOTFOUND	NSS_STATUS_NOTFOUND
#define NSS_UNAVAIL		NSS_STATUS_UNAVAIL
#define NSS_TRYAGAIN	NSS_STATUS_TRYAGAIN
#define NSS_RETURN		NSS_STATUS_RETURN

/* to let us index a lookup table on NSS_STATUSes */

#define _NSS_LOOKUP_OFFSET      NSS_STATUS_TRYAGAIN

#endif /* HAVE_NSSWITCH_H */

#ifndef _NSS_LOOKUP_OFFSET
#define _NSS_LOOKUP_OFFSET      (0)
#endif

typedef NSS_STATUS (*parser_t) (LDAPMessage *, ldap_state_t *, void *,
				char *, size_t);

#ifdef HPUX
extern int __thread_mutex_lock(pthread_mutex_t *);
extern int __thread_mutex_unlock(pthread_mutex_t *);
#endif /* HPUX */

#ifdef _AIX
extern int __multi_threaded;
#endif /* _AIX */

/*
 * Portable locking macro.
 */
#if defined(HAVE_THREAD_H) && !defined(_AIX) && !defined(__FreeBSD__)
#define NSS_LDAP_LOCK(m)		mutex_lock(&m)
#define NSS_LDAP_UNLOCK(m)		mutex_unlock(&m)
#define NSS_LDAP_DEFINE_LOCK(m)		static mutex_t m = DEFAULTMUTEX
#elif defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
#define NSS_LDAP_LOCK(m)		__libc_lock_lock(m)
#define NSS_LDAP_UNLOCK(m)		__libc_lock_unlock(m)
#define NSS_LDAP_DEFINE_LOCK(m)		static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#elif defined(HAVE_PTHREAD_H)
#ifdef HPUX
# define NSS_LDAP_LOCK(m)		__thread_mutex_lock(&m)
# define NSS_LDAP_UNLOCK(m)		__thread_mutex_unlock(&m)
# define NSS_LDAP_DEFINE_LOCK(m)		static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#elif defined(_AIX)
# define NSS_LDAP_LOCK(m)		do { \
						if (__multi_threaded) \
							pthread_mutex_lock(&m); \
					} while (0)
# define NSS_LDAP_UNLOCK(m)		do { \
						if (__multi_threaded) \
							pthread_mutex_unlock(&m); \
					} while (0)
# define NSS_LDAP_DEFINE_LOCK(m)		static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#elif defined(__FreeBSD__)
# define NSS_LDAP_LOCK(m)	      do { \
					       if (__isthreaded) \
						       pthread_mutex_lock(&m); \
				       } while (0)
# define NSS_LDAP_UNLOCK(m)	    do { \
					       if (__isthreaded) \
						       pthread_mutex_unlock(&m); \
				       } while (0)
# define NSS_LDAP_DEFINE_LOCK(m)	       static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#else
# define NSS_LDAP_LOCK(m)		pthread_mutex_lock(&m)
# define NSS_LDAP_UNLOCK(m)		pthread_mutex_unlock(&m)
# define NSS_LDAP_DEFINE_LOCK(m)		static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER
#endif /* HPUX || _AIX */
#else
#define NSS_LDAP_LOCK(m)
#define NSS_LDAP_UNLOCK(m)
#define NSS_LDAP_DEFINE_LOCK(m)
#endif

/*
 * Acquire global nss_ldap lock and blocks SIGPIPE.
 * Generally this should only be done within ldap-nss.c.
 */
void _nss_ldap_enter (void);

/*
 * Release global nss_ldap lock and blocks SIGPIPE.
 * Generally this should only be done within ldap-nss.c.
 */
void _nss_ldap_leave (void);

#ifdef LDAP_OPT_THREAD_FN_PTRS
/*
 * Netscape's libldap is threadsafe, but we use a
 * lock before it is initialized 
 */

struct ldap_error
{
  int le_errno;
  char *le_matched;
  char *le_errmsg;
};

typedef struct ldap_error ldap_error_t;

#endif /* LDAP_OPT_THREAD_FN_PTRS */

#ifdef HAVE_NSSWITCH_H
NSS_STATUS _nss_ldap_default_destr (nss_backend_t *, void *);
#endif

/*
 * context management routines.
 * _nss_ldap_default_constr() is called once in the constructor
 */
#ifdef HAVE_NSSWITCH_H
NSS_STATUS _nss_ldap_default_constr (nss_ldap_backend_t * be);
#endif

/* 
 * _nss_ldap_ent_context_init() is called for each getXXent() call
 * This will acquire the global mutex.
 */
ent_context_t *_nss_ldap_ent_context_init (ent_context_t **);

/*
 * _nss_ldap_ent_context_init_locked() has the same behaviour
 * as above, except it assumes that the caller has acquired
 * the lock
 */

ent_context_t *_nss_ldap_ent_context_init_locked (ent_context_t **);

/*
 * _nss_ldap_ent_context_init_internal_locked() has the same
 * behaviour, except it marks the context as one that's being
 * used to fetch additional data used in answering a request, i.e.
 * that this isn't the "main" context
 */

ent_context_t *_nss_ldap_ent_context_init_internal_locked (ent_context_t **);

/*
 * _nss_ldap_ent_context_release() is used to manually free a context 
 */
void _nss_ldap_ent_context_release (ent_context_t **);

/*
 * these are helper functions for ldap-grp.c only on Solaris
 */
char **_nss_ldap_get_values (LDAPMessage * e, const char *attr);
char *_nss_ldap_get_dn (LDAPMessage * e);
LDAPMessage *_nss_ldap_first_entry (LDAPMessage * res);
LDAPMessage *_nss_ldap_next_entry (LDAPMessage * res);
char *_nss_ldap_first_attribute (LDAPMessage * entry, BerElement **berptr);
char *_nss_ldap_next_attribute (LDAPMessage * entry, BerElement *ber);
const char **_nss_ldap_get_attributes (ldap_map_selector_t sel);

/*
 * Synchronous search cover (caller acquires lock).
 */
NSS_STATUS _nss_ldap_search_s (const ldap_args_t * args,	/* IN */
			       const char *filterprot,	/* IN */
			       ldap_map_selector_t sel,	/* IN */
			       const char **user_attrs, /* IN */
			       int sizelimit,	/* IN */
			       LDAPMessage ** pRes /* OUT */ );

/*
 * Asynchronous search cover (caller acquires lock).
 */
NSS_STATUS _nss_ldap_search (const ldap_args_t * args,	/* IN */
			     const char *filterprot,	/* IN */
			     ldap_map_selector_t sel,	/* IN */
			     const char **user_attrs, /* IN */
			     int sizelimit,	/* IN */
			     int *pMsgid, /* OUT */
  			     ldap_service_search_descriptor_t **s /*IN/OUT*/ );

/*
 * Emulate X.500 read operation.
 */
NSS_STATUS _nss_ldap_read (const char *dn,	/* IN */
			   const char **attributes,	/* IN */
			   LDAPMessage ** pRes /* OUT */ );

/*
 * extended enumeration routine; uses asynchronous API.
 * Caller must have acquired the global mutex
 */
NSS_STATUS _nss_ldap_getent_ex (ldap_args_t * args, /* IN */
				ent_context_t ** key,	/* IN/OUT */
				void *result,	/* IN/OUT */
				char *buffer,	/* IN */
				size_t buflen,	/* IN */
				int *errnop,	/* OUT */
				const char *filterprot,	/* IN */
				ldap_map_selector_t sel,	/* IN */
				const char **user_attrs, /* IN */
				parser_t parser /* IN */ );

/*
 * common enumeration routine; uses asynchronous API.
 * Acquires the global mutex
 */
NSS_STATUS _nss_ldap_getent (ent_context_t ** key,	/* IN/OUT */
			     void *result,	/* IN/OUT */
			     char *buffer,	/* IN */
			     size_t buflen,	/* IN */
			     int *errnop,	/* OUT */
			     const char *filterprot,	/* IN */
			     ldap_map_selector_t sel,	/* IN */
			     parser_t parser /* IN */ );

/*
 * common lookup routine; uses synchronous API.
 */
NSS_STATUS _nss_ldap_getbyname (ldap_args_t * args,	/* IN/OUT */
				void *result,	/* IN/OUT */
				char *buffer,	/* IN */
				size_t buflen,	/* IN */
				int *errnop,	/* OUT */
				const char *filterprot,	/* IN */
				ldap_map_selector_t sel,	/* IN */
				parser_t parser /* IN */ );

/* parsing utility functions */
NSS_STATUS _nss_ldap_assign_attrvals (LDAPMessage * e,	/* IN */
				      const char *attr,	/* IN */
				      const char *omitvalue,	/* IN */
				      char ***valptr,	/* OUT */
				      char **buffer,	/* IN/OUT */
				      size_t * buflen,	/* IN/OUT */
				      size_t * pvalcount /* OUT */ );

NSS_STATUS _nss_ldap_assign_attrval (LDAPMessage * e,	/* IN */
				     const char *attr,	/* IN */
				     char **valptr,	/* OUT */
				     char **buffer,	/* IN/OUT */
				     size_t * buflen /* IN/OUT */ );


const char *_nss_ldap_locate_userpassword (LDAPMessage *e, char **vals);

NSS_STATUS _nss_ldap_assign_userpassword (LDAPMessage * e,	/* IN */
					  const char *attr,	/* IN */
					  char **valptr,	/* OUT */
					  char **buffer,	/* IN/OUT */
					  size_t * buflen);	/* IN/OUT */

NSS_STATUS _nss_ldap_oc_check (LDAPMessage * e, const char *oc);

NSS_STATUS _nss_ldap_shadow_date(const char *val, long default_date,
				 long *value);
#if defined(HAVE_SHADOW_H)
void _nss_ldap_shadow_handle_flag(struct spwd *sp);
#else
#define _nss_ldap_shadow_handle_flag(_sp)	do { /* nothing */ } while (0)
#endif /* HAVE_SHADOW_H */

NSS_STATUS _nss_ldap_map_put (ldap_config_t * config,
			      ldap_map_selector_t sel,
			      ldap_map_type_t map,
			      const char *key, const char *value);

NSS_STATUS _nss_ldap_map_get (ldap_config_t * config,
			      ldap_map_selector_t sel,
			      ldap_map_type_t map,
			      const char *key, const char **value);

const char *_nss_ldap_map_at (ldap_map_selector_t sel, const char *pChar2);
const char *_nss_ldap_unmap_at (ldap_map_selector_t sel, const char *attribute);

const char *_nss_ldap_map_oc (ldap_map_selector_t sel, const char *pChar);
const char *_nss_ldap_unmap_oc (ldap_map_selector_t sel, const char *pChar);

const char *_nss_ldap_map_ov (const char *pChar);
const char *_nss_ldap_map_df (const char *pChar);

const char *_nss_ldap_map_mr (ldap_map_selector_t sel, const char *attribute);

/*
 * Proxy bind support for AIX.
 */
struct ldap_proxy_bind_args
{
  char *binddn;
  const char *bindpw;
};

typedef struct ldap_proxy_bind_args ldap_proxy_bind_args_t;

NSS_STATUS _nss_ldap_proxy_bind (const char *user, const char *password);

NSS_STATUS _nss_ldap_init (void);
void _nss_ldap_close (void);

int _nss_ldap_test_config_flag (unsigned int flag);
int _nss_ldap_test_initgroups_ignoreuser (const char *user);
int _nss_ldap_get_ld_errno (char **m, char **s);

const char *__nss_ldap_status2string (NSS_STATUS stat);

ldap_session_mech_t __nss_ldap_mech_setup(ldap_session_mech_type_t mechType,
 					  ldap_session_mech_init_t initFunc,
 					  ldap_session_mech_select_t selectFunc,
 					  ldap_session_mech_restore_t restoreFunc,
 					  ldap_session_mech_close_t closeFunc);
 
ldap_session_mech_t __nss_ldap_krb5_cache();
 
/*
 * Support addition of opaque structures for subsystems
 */
ldap_session_opaque_t __nss_ldap_find_opaque(ldap_session_t *session,
					     ldap_session_opaque_type_t opaque_type);
ldap_session_opaque_t __nss_ldap_add_opaque(ldap_session_t *session,
					    ldap_session_opaque_type_t opaque_type,
					    ldap_session_opaque_t current);
ldap_session_opaque_t __nss_ldap_allocate_opaque(ldap_session_t *session,
					         ldap_session_opaque_type_t opaque_type);
ldap_session_opaque_t __nss_ldap_remove_opaque(ldap_session_t *session,
					       ldap_session_opaque_type_t opaque_type);
void __nss_ldap_free_opaque(ldap_session_t *session, ldap_session_opaque_type_t opaque_type);

#endif /* _LDAP_NSS_LDAP_LDAP_NSS_H */
