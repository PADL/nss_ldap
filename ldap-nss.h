/* Copyright (C) 1997 Luke Howard.
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

#ifdef GNU_NSS
#include <errno.h>
#include <pthread.h>
#endif /* GNU_NSS */

#ifdef DEBUG
#ifdef DEBUG_SYSLOG
#include <syslog.h>
#define debug(str) syslog(LOG_DEBUG, "nss_ldap - thread %u  - %s", thr_self(), str)
#else
#define debug(str) fprintf(stderr, "%s\n", str)
#endif /* DEBUG_SYSLOG */
#else
#define debug(str)
#endif /* DEBUG */

#ifdef __GNUC__
#define alignof(ptr) __alignof__(ptr)
#define INLINE inline
#elif defined(OSF1)
#include <alignof.h>
#define INLINE
#else
#define INLINE
#endif /* __GNUC__ */

#ifdef DL_NSS
#ifndef GNU_NSS
#define GNU_NSS
#endif
#define __set_errno(e)  do { errno = e; } while (0)
#endif /* DL_NSS */

#if defined(GNU_NSS) || defined(SUN_NSS)
#define HAVE_STRTOK_R
#endif

#ifndef alignof

#define align(ptr, blen)
#define bytesleft(ptr, blen)    (blen)

#else

#define align(ptr, blen)              do { \
					char *qtr = ptr; \
					ptr += alignof(char *) - 1; \
					ptr -= ((ptr - (char *)NULL) % alignof(char *)); \
					blen -= (ptr - qtr); \
				} while (0)

/* worst case */
#define bytesleft(ptr, blen)    (blen - alignof(char *) + 1)

#endif

#ifdef GNU_NSS
# if !defined(TESTING) && !defined(DL_NSS)
#  if (__GLIBC__ == 2) && (__GLIBC_MINOR__ > 0)
#   include <bits/libc-lock.h>
#  else
#   include <libc-lock.h>
#  endif
# endif
#endif

/*
 * linked list of configurations pointing to LDAP servers. The first
 * which has a successful ldap_open() is used. Conceivably the rest
 * could be used after a failed or exhausted search.
 */
struct ldap_config
{
	/* space delimited list of servers */
	char *ldc_host;
	/* port, expected to be common to all servers */
	int ldc_port;
	/* base DN, eg. dc=gnu,dc=org */
	char *ldc_base;
	/* scope for searches */
	int ldc_scope;
	char *ldc_binddn;
	char *ldc_bindpw;
	/* protocol version */
	int ldc_version;
	/* next configuration. loops back onto itself for last
	   entry
	 */
	struct ldap_config *ldc_next;
};

typedef struct ldap_config ldap_config_t;

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
};

typedef struct ldap_session ldap_session_t;

/*
 * glibc supports MD5 encryption. So we should recognise it. This
 *  is configurable at runtime by putting crypt [md5|crypt|sha] in
 * /etc/ldap.conf.
 */
enum crypt_prefix
{
	UNIX_CRYPT,
	SHA_CRYPT,
	MD5_CRYPT
};

typedef enum crypt_prefix crypt_prefix_t;

#if !defined(SUN_NSS)
#ifndef UID_NOBODY
#define UID_NOBODY      (-2)
#endif
#ifndef GID_NOBODY
#define GID_NOBODY     (-2)
#endif
#endif

enum ldap_args_types
{
	LA_TYPE_STRING,
	LA_TYPE_NUMBER,
	LA_TYPE_STRING_AND_STRING,
	LA_TYPE_NUMBER_AND_STRING
};

typedef enum ldap_args_types ldap_args_types_t;

struct ldap_args
{
	ldap_args_types_t la_type;
	union {
		const char *la_string;
		long la_number;
	} la_arg1;
	union {
		const char *la_string;
	} la_arg2;
};

typedef struct ldap_args ldap_args_t;

#define LA_INIT(q)				do { \
						q.la_type = LA_TYPE_STRING; \
						q.la_arg1.la_string = NULL; \
						q.la_arg2.la_string = NULL; \
						} while (0)
#define LA_TYPE(q)				(q.la_type)
#define LA_STRING(q)				(q.la_arg1.la_string)
#define LA_NUMBER(q)				(q.la_arg1.la_number)
#define LA_STRING2(q)				(q.la_arg2.la_string)

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
#define LS_TYPE_KEY	(0)
#define LS_TYPE_INDEX	(1)
	union {
	/* ls_key is the requested attribute value.
	   ls_index is the desired offset into the value list.
	 */
		const char *ls_key;
		int ls_index;
	} ls_info;
};

typedef struct ldap_state ldap_state_t;
/*
 * LS_INIT only used for enumeration contexts
 */
#define LS_INIT(state)	do { state.ls_type = LS_TYPE_INDEX; state.ls_info.ls_index = -1; } while (0)

/*
 * thread specific context: result chain, and state data
 */
struct ent_context
{
	ldap_state_t ec_state;		/* eg. for services */
	LDAPMessage *ec_res;		/* result chain */
	LDAPMessage *ec_last;		/* current result pointer */
};

typedef struct ent_context ent_context_t;

/*
 * this is just a pointer to a context, used by the allocation and 
 * destruction functions, so we can allocate it properly and maybe
 * destroy it & reset the pointer to NULL. (We don't free the memory
 * at the moment, we reuse it next time.)
 */
typedef ent_context_t *context_handle_t;

#ifdef SUN_NSS
struct nss_ldap_backend
{
	nss_backend_op_t *ops;
	int n_ops;
	context_handle_t state;
};

typedef struct nss_ldap_backend nss_ldap_backend_t;
#endif

#if defined(IRS_NSS) || defined(DL_NSS)

typedef enum {
	NSS_SUCCESS,
	NSS_NOTFOUND,
	NSS_UNAVAIL,
	NSS_TRYAGAIN
} NSS_STATUS;

#elif defined(GNU_NSS)

typedef enum nss_status NSS_STATUS;

#define NSS_SUCCESS		NSS_STATUS_SUCCESS
#define NSS_NOTFOUND	NSS_STATUS_NOTFOUND
#define NSS_UNAVAIL		NSS_STATUS_UNAVAIL
#define NSS_TRYAGAIN	NSS_STATUS_TRYAGAIN

/* to let us index a lookup table on NSS_STATUSes */

#define _NSS_LOOKUP_OFFSET      NSS_STATUS_TRYAGAIN

#else
typedef nss_status_t NSS_STATUS;
#endif

#ifndef _NSS_LOOKUP_OFFSET
#define _NSS_LOOKUP_OFFSET      (0)
#endif

#ifdef GNU_NSS
#if defined(TESTING) || defined(DL_NSS)
# define __nss_lock()
# define __nss_unlock()
# define __nss_cleanup()
#else
# define __nss_lock()		__libc_lock_lock(_nss_ldap_lock)
# define __nss_unlock()		__libc_lock_unlock(_nss_ldap_lock)
# define __nss_cleanup()
#endif /* TESTING */
#elif defined(IRS_NSS)
/* XXX no mutex support */
#define __nss_lock()
#define __nss_unlock()
#define __nss_cleanup()
#else
#define __nss_lock()		mutex_lock(&_nss_ldap_lock)
#define __nss_unlock()		mutex_unlock(&_nss_ldap_lock)
#define __nss_cleanup()		do { \
					(void) mutex_destroy(&_nss_ldap_lock); \
				} while (0)
#endif

typedef NSS_STATUS (*parser_t)(LDAP *, LDAPMessage *, ldap_state_t *, void *, char *, size_t);

#ifdef LDAP_VERSION3_API
/*
 * Netscape's libldap is threadsafe, but we use a lock before it is initialized 
 */

struct ldap_error
{
	int le_errno;
	char *le_matched;
	char *le_errmsg;
};

typedef struct ldap_error ldap_error_t;

#define nss_libldap_lock()
#define nss_libldap_unlock()

#else

#define nss_libldap_lock()		__nss_lock()
#define nss_libldap_unlock()		__nss_unlock()

#endif /* LDAP_VERSION3_API */

#ifdef SUN_NSS
/* paranoia - maybe we do need to lock it */
#define nss_context_lock()	__nss_lock()
#define nss_context_unlock()	__nss_unlock()

/* (Solaris) we leak a mutex at the expense of avoiding race conditions. */
#define nss_cleanup()

#else 

#define nss_context_lock()	__nss_lock()
#define nss_context_unlock()	__nss_unlock()
#define nss_cleanup()

#endif


#ifdef SUN_NSS
NSS_STATUS _nss_ldap_default_destr(nss_backend_t *, void *);
#endif


/*
 * context management routines.
 * _nss_ldap_default_constr() is called once in the constructor
 * ent_context_init() is called for each getXXent() call
 * ent_context_free() is used to manually free a context
 */
#ifdef SUN_NSS
NSS_STATUS _nss_ldap_default_constr(nss_ldap_backend_t *be);
#endif

ent_context_t *_nss_ldap_ent_context_init(context_handle_t *);
void _nss_ldap_ent_context_free(context_handle_t *);

LDAPMessage *_nss_ldap_lookup(
	const ldap_args_t *args,  /* IN */
	const char *filterprot, /* IN */
	const char **attributes /* IN */,
	int sizelimit);

LDAPMessage *_nss_ldap_read(
	const char *dn,
	const char **attributes);

/* common enumeration routine */
NSS_STATUS _nss_ldap_getent(
	ent_context_t *key, /* IN/OUT */
	void *result, /* IN/OUT */
	char *buffer, /* IN */
	size_t buflen, /* IN */
	int *errnop, /* OUT */
	const char *filterprot, /* IN */
	const char **attrs, /* IN */
	parser_t parser /* IN */);

/* common lookup routine */
NSS_STATUS _nss_ldap_getbyname(
	ldap_args_t *args, /* IN/OUT */
	void *result, /* IN/OUT */
	char *buffer, /* IN */
	size_t buflen, /* IN */
	int *errnop, /* OUT */
	const char *filterprot, /* IN */
	const char **attrs, /* IN */
	parser_t parser /* IN */);

/* parsing utility functions */
NSS_STATUS _nss_ldap_assign_attrvals(
	LDAP *ld, /* IN */
	LDAPMessage *e, /* IN */
	const char *attr, /* IN */
	const char *omitvalue, /* IN */
	char ***valptr, /* OUT */
	char **buffer, /* IN/OUT */
	size_t *buflen, /* IN/OUT */
	size_t *pvalcount /* OUT */);

NSS_STATUS _nss_ldap_assign_attrval(
	LDAP *ld,  /* IN */
	LDAPMessage *e, /* IN */
	const char *attr, /* IN */
	char **valptr, /* OUT */
	char **buffer, /* IN/OUT */
	size_t *buflen /* IN/OUT */);


NSS_STATUS _nss_ldap_assign_passwd(
	LDAP *ld, /* IN */
	LDAPMessage *e, /* IN */
	const char *attr, /* IN */
	char **valptr, /* OUT */
	char **buffer, /* IN/OUT */
	size_t *buflen); /* IN/OUT */

#endif /* _LDAP_NSS_LDAP_LDAP_NSS_H */

