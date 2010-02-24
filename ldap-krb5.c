/* Copyright (C) 2007-2010 Howard Wilkinson
   Copyright (C) 2007 Markus Moeller
   Copyright (C) 2007 Luke Howard
   This file is part of the nss_ldap library
   Contributed by Howard Wilkinson <howard@cohtech.com>, 2010.

   Derived from original version by Markus Moeller <huaraz@moeller.plus.com>

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

/*
 * This file implements the management of the Kerberos Credential Cache
 * for SASL connections.
 *
 * The init function implements a finite state machine which is designed to
 * manage the various configuration states that the Kerberos environment
 * can be in.
 */

/*
 * INIT:	Initial state when first called and also state after a reset.
 *		Calls krb5_cache_setup which populates the environment
 *		 => REFRESH - Try to load some credentials first
 * RUNNING:	Credentials have been loaded and are current.
 *		 => EXPIRED - Cached credentials have expired
 *		 => REFRESH - Cached credentials are expiring
 *		 => INIT    - escape path for inconsistent data
 *				(should never happen)
 * RENEW:	Credentials are expiring and have not been externally refreshed
 *		 => ERROR   - Autorenew is not on so this is an error state
 *		 => EXPIRED - Cached credentials expired during renewal
 *		 => RUNNING - Cached credentials have been successfully renewed
 * EXPIRED:	Credentials have expired acquire new ones.
 *		This only works if a keytab is configured and useable.
 *		 => ERROR   - No available keytab or keytab is not useable
 *		 => RUNNING - New credentials acquired
 * REFRESH:	Reload credentials from the configured credential cache
 *		 => RUNNING - New credentials loaded and not expired
 *		 => RENEW   - New credentials loaded but are expiring
 *				(only happens if autorenew is on)
 *		 => EXPIRED - New credentials loaded have expired
 *				or are expiring and autorenew is off
 *		 => ERROR   - Inconsistent credentials state
 *		 => ACQUIRE - Cannot load any usable credentials from a cache
 *				Try for a keytab if one is configured
 * ACQUIRE:	No credentials loaded acquire new ones - (See EXPIRED)
 * ERROR:	Call reset and then return failure from this attempt
 *		 => REFRESH
 */

/*
 * The code is written to allow an external program to supply credentials
 * in the environment. This program can refresh/renew the credentials
 * periodically and we will use these.
 * As an alternative this code can renew externally provided credentials
 * if necessary - autorenew must be turned on.
 * Finally if provided with a keytab this code will acquire credentials
 * from a KDC
 */

/*
 * 23rd October 2009 -  Incorporated changes suggested by Luke Howard.
 * 4th December 2008 -	Removed static variables as part of making code
 *			reentrant/thread safe.
 * 31st July 2007 -	Initial, non-thread safe, implementation
 */

#include "config.h"
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#include "ldap-nss.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <krb5.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#ifndef HEIMDAL
#include <profile.h>
#endif
#ifdef HEIMDAL
#define error_message(code) krb5_get_err_text(context,code)
#endif
#include <sys/types.h>
#include <assert.h>
#if defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#elif defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#endif

#define MAX_RENEW_TIME "365d"

#define KT_PATH_MAX 256

#ifndef HEIMDAL
typedef struct _profile_t *profile_t;
#endif

#if defined(CONFIGURE_KRB5_KEYTAB)
/* State machine items */
typedef enum
{
  KRB5_CACHE_INIT = 0,		/* First time through or has been reset */
  KRB5_CACHE_RUNNING,		/* Valid non-expired credentials loaded */
  KRB5_CACHE_RENEW,		/* Valid about to expire credentials loaded */
  KRB5_CACHE_EXPIRED,		/* Valid expired credentials loaded */
  KRB5_CACHE_REFRESH,		/* No credentials loaded */
  KRB5_CACHE_ACQUIRE,		/* Acquire new credentials from KDC */
  KRB5_CACHE_ERROR		/* Cannot get any credentials (this time) */
} krb5_cache_state;

typedef struct _nss_ldap_krb5_state {
  krb5_cache_state	cache_state;
  uid_t			euid;
  krb5_context		context;
  krb5_creds		*creds;
#ifdef HEIMDAL
  krb5_creds		*creds2;
#endif
  krb5_principal	principal;
  krb5_ccache		cc;
  krb5_deltat		skew;
  char			*ccname;
  char			*saveccname;
  char			*ktname;
  char			*saslid;
  int			autorenew;
} _nss_ldap_krb5_state, *_nss_ldap_krb5_state_p;

#define credsOK(__ks__)				\
  (((__ks__)->creds != NULL) && (((__ks__)->creds->times.endtime - time(0)) > (2 * (__ks__)->skew)))

#define credsEXPIRING(__ks__)			\
  (((__ks__)->creds != NULL)			\
   && ((((__ks__)->creds->times.endtime - time(0)) <= (2 * (__ks__)->skew)) \
       && (((__ks__)->creds->times.endtime - time(0)) > (__ks__)->skew)))

#define credsEXPIRED(__ks__)			\
  (((__ks__)->creds == NULL)			\
   || ((((__ks__)->creds->times.renew_till - time(0)) <= (2 * (__ks__)->skew)) \
       || (((__ks__)->creds->times.endtime - time(0)) <= (__ks__)->skew)))

static void *__nss_ldap_krb5_cache_init(ldap_session_t *session);
static int __nss_ldap_krb5_cache_select (ldap_session_t *session);
static int __nss_ldap_krb5_cache_restore (ldap_session_t *session);
static void __nss_ldap_krb5_cache_close(ldap_session_t *session);

static void
__nss_ldap_krb5_cache_reset (_nss_ldap_krb5_state_p krb5_cache_state)
{
  debug ("==> __nss_ldap_krb5_cache_reset");

  assert(krb5_cache_state != NULL);

  if (krb5_cache_state->context != NULL)
    {
      if (krb5_cache_state->creds != NULL)
	{
	  debug (":== __nss_ldap_krb5_cache_reset: call krb5_free_creds");
	  krb5_free_creds (krb5_cache_state->context, krb5_cache_state->creds);
	  krb5_cache_state->creds = NULL;
	}
#ifdef HEIMDAL
      if (krb5_cache_state->creds2 != NULL)
	{
	  debug (":== __nss_ldap_krb5_cache_reset: call krb5_free_creds");
	  krb5_free_creds (krb5_cache_state->context, krb5_cache_state->creds2);
	  krb5_cache_state->creds2 = NULL;
	}
#endif
      if (krb5_cache_state->principal != NULL)
	{
	  debug (":== __nss_ldap_krb5_cache_reset: call krb5_free_principal");
	  krb5_free_principal (krb5_cache_state->context, krb5_cache_state->principal);
	  krb5_cache_state->principal = NULL;
	}
      if (krb5_cache_state->cc != NULL)
	{
	  krb5_cc_close (krb5_cache_state->context, krb5_cache_state->cc);
	  krb5_cache_state->cc = NULL;
	}

      krb5_free_context (krb5_cache_state->context);
      krb5_cache_state->context = NULL;
    }

  krb5_cache_state->skew = 0;
  krb5_cache_state->autorenew = 0;

  if (krb5_cache_state->ccname != NULL)
    {
      free (krb5_cache_state->ccname);
      krb5_cache_state->ccname = NULL;
    }
  if (krb5_cache_state->ktname != NULL)
    {
      free (krb5_cache_state->ktname);
      krb5_cache_state->ktname = NULL;
    }
  if (krb5_cache_state->saslid != NULL)
    {
      free (krb5_cache_state->saslid);
      krb5_cache_state->saslid = NULL;
    }

  krb5_cache_state->cache_state = KRB5_CACHE_INIT;

  debug ("<== __nss_ldap_krb5_cache_reset");

  return;
}

static char *
__nss_ldap_krb5_cache_get_ktname (_nss_ldap_krb5_state_p krb5_cache_state, ldap_config_t * config)
{
  char *ktname = NULL;
  char buf[KT_PATH_MAX];

  assert(krb5_cache_state != NULL && config != NULL);

  debug ("==> __nss_ldap_krb5_cache_get_ktname rootusekeytab = %d, rootusesasl = %d, rootkeytabname = %s",
	 config->ldc_krb5_rootusekeytab, config->ldc_rootusesasl, config->ldc_krb5_rootkeytabname);
  debug ("==> __nss_ldap_krb5_cache_get_ktname usekeytab = %d, usesasl = %d, keytabname = %s",
	 config->ldc_krb5_usekeytab, config->ldc_usesasl, config->ldc_krb5_keytabname);

  if (krb5_cache_state->euid == 0 &&
      config->ldc_krb5_rootusekeytab &&
      config->ldc_rootusesasl)
    {
      ktname = config->ldc_krb5_rootkeytabname;
    }

  if (ktname == NULL &&
      config->ldc_krb5_usekeytab &&
      config->ldc_usesasl)
    {
      ktname = config->ldc_krb5_keytabname;
    }

  if (ktname == NULL &&
      getuid() == geteuid() &&
      getgid() == getegid())
    {
      /* Not setuid, so safe to read environment variables or use defaults */
      ktname = getenv ("KRB5_KTNAME");
      if (ktname == NULL)
	{
	  ktname = getenv ("NSS_LDAP_KRB5_KTNAME");
	}

      debug (":== __nss_ldap_krb5_cache_get_ktname: call krb5_kt_default_name");

      assert(krb5_cache_state->context != NULL);

      if (krb5_kt_default_name (krb5_cache_state->context, buf, KT_PATH_MAX) == 0)
	{
	  ktname = buf;
	}
    }

  debug ("<== __nss_ldap_krb5_cache_get_ktname: returns %s",
	 ktname ? ktname : "NULL");

  return ktname != NULL ? strdup(ktname) : NULL;
}

static char *
__nss_ldap_krb5_cache_get_ccname (_nss_ldap_krb5_state_p krb5_cache_state, ldap_config_t * config)
{
  char *ccname = NULL;

  debug ("==> __nss_ldap_krb5_cache_get_ccname");

  assert(krb5_cache_state != NULL && config != NULL && krb5_cache_state->context != NULL);

  if (krb5_cache_state->euid == 0 && config->ldc_rootusesasl)
    {
      ccname = config->ldc_krb5_rootccname;
    }

  if (ccname == NULL && config->ldc_usesasl)
    {
      ccname = config->ldc_krb5_ccname;
    }

  if (ccname == NULL &&
      getuid() == geteuid() &&
      getgid() == getegid())
    {
      /* Not setuid, so safe to read environment variables */
      ccname = getenv ("KRB5CCNAME");
      if (ccname == NULL)
	{
	  ccname = getenv ("NSS_LDAP_KRB5CCNAME");
	}

      if (ccname == NULL)
	{
	  ccname = (char *)krb5_cc_default_name (krb5_cache_state->context);
	}
    }

  debug ("<== __nss_ldap_krb5_cache_get_ccname: returns ccname = %s",
	 ccname ? ccname : "NULL");

  return (ccname != NULL) ? strdup (ccname) : NULL;
}

static char *
__nss_ldap_krb5_cache_get_saslid (_nss_ldap_krb5_state_p krb5_cache_state, ldap_config_t * config)
{
  char *saslid = NULL;
  char defaultSaslId[sizeof("host/") + MAXHOSTNAMELEN] = "host/";

  debug ("==> __nss_ldap_krb5_cache_get_saslid");

  assert (krb5_cache_state != NULL && config != NULL);

  if (krb5_cache_state->euid == 0 && config->ldc_rootusesasl)
    {
      saslid = config->ldc_rootsaslid;
    }

  if (saslid == NULL && config->ldc_usesasl)
    {
      saslid = config->ldc_saslid;
    }

  if (saslid == NULL)
    {
      char *p;
      int hostnamelen;

      debug (":== __nss_ldap_krb5_cache_get_saslid: get default principal name");

      p = &defaultSaslId[sizeof("host/") - 1];

      if (gethostname (p, MAXHOSTNAMELEN) != 0)
	{
	  debug ("<== _nss_ldap_krb5_cache_get_saslid: gethostname() failed - %s", strerror(errno));
	  return NULL;
	}

      hostnamelen = strlen (p);

      if (strchr (p, '.') == NULL)
	{
	  if (getdomainname (p + 1, MAXHOSTNAMELEN - hostnamelen - 1) != 0)
	    {
	      debug ("<== _nss_ldap_krb5_cache_get_saslid: getdomainname() failed - %s", strerror(errno));
	      return NULL;
	    }

	  *p = '.';
	}

      saslid = defaultSaslId;
    }

  debug ("<== __nss_ldap_krb5_cache_get_saslid: returns %s", saslid);
    
  return (saslid != NULL) ? strdup(saslid) : NULL;
}

static krb5_principal
__nss_ldap_krb5_cache_get_principal (_nss_ldap_krb5_state_p krb5_cache_state)
{
  krb5_error_code code;
  krb5_principal principal;

  debug ("==> __nss_ldap_krb5_cache_get_principal");

  assert (krb5_cache_state->context != NULL && krb5_cache_state->saslid != NULL);

  debug (":== __nss_ldap_krb5_cache_get_principal: call krb5_parse_name");

  code = krb5_parse_name (krb5_cache_state->context, krb5_cache_state->saslid, &principal);
  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_get_principal: %s(%d) while parsing principal name %s",
	     error_message (code), (int) code, krb5_cache_state->saslid);
      return NULL;
    }

  debug ("<== __nss_ldap_krb5_cache_get_principal: returns %p", principal);
  return principal;
}

/* Set up to manage the credentials cache */
static krb5_error_code
__nss_ldap_krb5_cache_setup (_nss_ldap_krb5_state_p krb5_cache_state, ldap_config_t * config)
{
  krb5_error_code code = 0;
#ifndef HEIMDAL
  profile_t profile;
#endif

  debug ("==> __nss_ldap_krb5_cache_setup");

  assert(krb5_cache_state != NULL && config != NULL);

  if (krb5_cache_state->context == NULL)
    {
      debug (":== __nss_ldap_krb5_cache_setup: call krb5_init_context");

      code = krb5_init_context (&(krb5_cache_state->context));
      if (code != 0)
	{
	  debug ("<== __nss_ldap_krb5_cache_setup: %s(%d) while initialising Kerberos library",
		 error_message (code), (int) code);
	  return code;
	}
    }
#ifndef HEIMDAL
  debug (":== __nss_ldap_krb5_cache_setup: call krb5_get_profile");

  code = krb5_get_profile (krb5_cache_state->context, &profile);
  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_setup: %s(%d) while getting profile",
	     error_message (code), (int) code);
      return code;
    }

  debug (":== __nss_ldap_krb5_cache_setup: call profile_get_integer");

  code = profile_get_integer (profile,
			      "libdefaults",
			      "clockskew", 0, 5 * 60, &(krb5_cache_state->skew));

  debug (":== __nss_ldap_krb5_cache_setup: profile_get_integer returns %d", code);

  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_setup: %s(%d) while getting clockskew",
	     error_message (code), (int) code);
      return code;
    }

  debug (":== __nss_ldap_krb5_cache_setup: call profile_release");
  profile_release (profile);
#else
  krb5_cache_state->skew = krb5_cache_state->context->max_skew;
#endif
  krb5_cache_state->autorenew = (config->ldc_krb5_autorenew
				 || (krb5_cache_state->euid == 0 && config->ldc_krb5_rootautorenew));

  krb5_cache_state->ktname = __nss_ldap_krb5_cache_get_ktname (krb5_cache_state, config);

  debug (":== __nss_ldap_krb5_cache_setup: keytab name %s",
	 krb5_cache_state->ktname ? krb5_cache_state->ktname : "NULL");

  krb5_cache_state->ccname = __nss_ldap_krb5_cache_get_ccname (krb5_cache_state, config);

  debug (":== __nss_ldap_krb5_cache_setup: credential cache name %s",
	 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
  krb5_cache_state->cache_state = KRB5_CACHE_REFRESH;

  debug ("<== __nss_ldap_krb5_cache_setup");

  return 0;
}

static int
__nss_ldap_krb5_cache_setup_creds (_nss_ldap_krb5_state_p krb5_cache_state)
{
  debug ("==> __nss_ldap_krb5_cache_setup_creds");

  assert(krb5_cache_state != NULL);

  if (krb5_cache_state->creds == NULL)
    {
      krb5_cache_state->creds = malloc (sizeof (*(krb5_cache_state->creds)));
      if (krb5_cache_state->creds == NULL)
	{
	  debug ("<== __nss_ldap_krb5_cache_setup_creds: out of memory while allocating cache creds");
	  return -1;
	}
    }

  memset (krb5_cache_state->creds, 0, sizeof (*(krb5_cache_state->creds)));

  debug ("<== __nss_ldap_krb5_cache_setup_creds");

  return 0;
}

/* (Re)load the credentials cache into our local data */
static int
__nss_ldap_krb5_cache_refresh (_nss_ldap_krb5_state_p krb5_cache_state)
{

  krb5_error_code code;

  debug ("==> __nss_ldap_krb5_cache_refresh");

  assert(krb5_cache_state != NULL);
  assert(krb5_cache_state->ccname != NULL);
  assert(krb5_cache_state->cc == NULL);

  debug (":== __nss_ldap_krb5_cache_refresh %s", krb5_cache_state->ccname);

  code = krb5_cc_resolve (krb5_cache_state->context, krb5_cache_state->ccname, &krb5_cache_state->cc);
  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_refresh: cache %s cannot be resolved",
	     krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
    }
  else
    {
      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_cc_get_principal");

      code = krb5_cc_get_principal (krb5_cache_state->context,
				    krb5_cache_state->cc,
				    &krb5_cache_state->principal);
      if (code != 0)
	{
	  debug (":== __nss_ldap_krb5_cache_refresh: cannot get principal from cache %s",
		 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
	}
      else
	{
	  /* Use the principal name from the cache rather than preconfigured saslid */
	  char *principal_name = NULL;

	  debug (":== __nss_ldap_krb5_cache_refresh: found existing cache %s call krb5_unparse_name",
		 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");

	  code = krb5_unparse_name (krb5_cache_state->context, krb5_cache_state->principal, &principal_name);

	  debug (":== __nss_ldap_krb5_cache_refresh: krb5_unparse_name returns %d", code);

	  if (code != 0)
	    {
	      debug (":== __nss_ldap_krb5_cache_refresh: cannot unparse principal from cache %s",
		     krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
	    }
	  else
	    {
	      krb5_cc_cursor cursor;

	      debug (":== __nss_ldap_krb5_cache_refresh: cache %s principal %s call krb5_cc_start_seq_get",
		     krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL",
		     principal_name ? principal_name : "NULL");

	      code = krb5_cc_start_seq_get (krb5_cache_state->context, krb5_cache_state->cc, &cursor);

	      debug (":== __nss_ldap_krb5_cache_refresh: krb5_cc_start_seq_get returns %d", code);

	      if (code != 0)
		{
		  debug (":== __nss_ldap_krb5_cache_refresh: cache %s credentials not usable",
			 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
		}
	      else
		{
		  if (__nss_ldap_krb5_cache_setup_creds (krb5_cache_state))
		    {
		      debug ("<== __nss_ldap_krb5_cache_refresh: failed to setup creds");
		      return 1;
		    }
		  while (krb5_cache_state->cache_state == KRB5_CACHE_REFRESH)
		    {
		      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_cc_next_cred");

		      code = krb5_cc_next_cred (krb5_cache_state->context,
						krb5_cache_state->cc,
						&cursor,
						krb5_cache_state->creds);

		      debug (":== __nss_ldap_krb5_cache_refresh: krb5_cc_next_cred returns %d", code);

		      if (code != 0)
			{
			  break;
			}

		      debug (":== __nss_ldap_krb5_cache_refresh: retrieved creds");

		      if (credsOK (krb5_cache_state))
			{
			  debug (":== __nss_ldap_krb5_cache_refresh: creds are OK --> RUNNING");
			  /* Reloaded cache is fine */
			  krb5_cache_state->cache_state = KRB5_CACHE_RUNNING;
			  break;
			}

		      if (credsEXPIRING (krb5_cache_state))
			{
			  debug (":== __nss_ldap_krb5_cache_refresh: creds are EXPIRING");
			  /* Reloaded cache will expire shortly */
			  if (krb5_cache_state->autorenew)
			    {
			      debug (":== __nss_ldap_krb5_cache_refresh: --> RENEW");
			      krb5_cache_state->cache_state = KRB5_CACHE_RENEW;
			    }
			  else
			    {
			      debug (":== __nss_ldap_krb5_cache_refresh: --> EXPIRED");
			      krb5_cache_state->cache_state = KRB5_CACHE_EXPIRED;
			    }
			  goto next_creds;
			}

		      if (credsEXPIRED (krb5_cache_state))
			{
			  debug (":== __nss_ldap_krb5_cache_refresh: creds have EXPIRED --> EXPIRED");
			  /* Reload cache has expired */
			  krb5_cache_state->cache_state = KRB5_CACHE_EXPIRED;
			  goto next_creds;
			}

		      /*
		       * Should never happen
		       * This is a logic error if we get here - so force a reset
		       */
		      debug (":== __nss_ldap_krb5_cache_refresh: creds in weird state --> ERROR");
		      krb5_cache_state->cache_state = KRB5_CACHE_ERROR;

		    next_creds:
		      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_free_cred_contents");
		      krb5_free_cred_contents (krb5_cache_state->context, krb5_cache_state->creds);
		    }
		  debug (":== __nss_ldap_krb5_cache_refresh: call krb5_cc_end_seq_get");

		  code = krb5_cc_end_seq_get (krb5_cache_state->context, krb5_cache_state->cc, &cursor);

		  debug (":== __nss_ldap_krb5_cache_refresh: krb5_cc_end_seq_get returns %d", code);

		  if (code != 0)
		    {
		      debug (":== __nss_ldap_krb5_cache_refresh: cache %s scan failed to end cleanly",
			     krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
		    }
		}
	      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_free_unparsed_name");

	      krb5_free_unparsed_name (krb5_cache_state->context, principal_name);

	    }
	}
    }

  if (krb5_cache_state->principal != NULL)
    {
      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_free_principal");

      krb5_free_principal (krb5_cache_state->context, krb5_cache_state->principal);
      krb5_cache_state->principal = NULL;
    }
  if (krb5_cache_state->cc != NULL)
    {
      debug (":== __nss_ldap_krb5_cache_refresh: call krb5_cc_close");

      code = krb5_cc_close (krb5_cache_state->context, krb5_cache_state->cc);
      if (code != 0)
	{
	  debug (":== __nss_ldap_krb5_cache_refresh: cache %s close failed",
		 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
	}
      krb5_cache_state->cc = NULL;
    }
  if (krb5_cache_state->cache_state == KRB5_CACHE_REFRESH)
    {
      debug (":== __nss_ldap_krb5_cache_refresh: stuck in refresh --> ACQUIRE");
      krb5_cache_state->cache_state = KRB5_CACHE_ACQUIRE;	/* Try for a keytab */
    }

  debug ("<== __nss_ldap_krb5_cache_refresh");

  return code;
}

/* Renew an expired credentials cache */
static int
__nss_ldap_krb5_cache_renew (_nss_ldap_krb5_state_p krb5_cache_state)
{

  krb5_error_code code = 0;

#ifdef HEIMDAL
  krb5_kdc_flags flags;
  krb5_realm *client_realm;
#endif

  debug ("==> __nss_ldap_krb5_cache_renew");

  assert(krb5_cache_state != NULL);

  if (!krb5_cache_state->autorenew)
    {
      /*
       * We should never get here
       * as the refresh code should only enter renew
       * if autorenew is true
       */
      debug ("<== __nss_ldap_krb5_cache_renew: renew called with autorenew off --> ERROR");
      krb5_cache_state->cache_state = KRB5_CACHE_ERROR;
      return 1;
    }

  assert (krb5_cache_state->context != NULL && krb5_cache_state->creds != NULL);	/* Refresh or acquire will have set this up */
  /* renew ticket */
#ifndef HEIMDAL
  /* Overwrites contents of creds no storage allocation happening */
  assert(krb5_cache_state->principal != NULL && krb5_cache_state->cc != NULL);

  debug (":== __nss_ldap_krb5_cache_renew: call krb5_get_renewed_creds");

  code = krb5_get_renewed_creds (krb5_cache_state->context,
				 krb5_cache_state->creds,
				 krb5_cache_state->principal,
				 krb5_cache_state->cc,
				 NULL);

  debug (":== __nss_ldap_krb5_cache_renew: krb5_get_renewed_creds returns %d", code);

  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_renew: failed to renew creds %s(%d)",
	     error_message (code), (int) code);
#else
  flags.i = 0;
  flags.b.renewable = flags.b.renew = 1;
  if (krb5_cache_state->creds2 == NULL)
    {
      krb5_cache_state->creds2 = (krb5_creds*)malloc(sizeof(krb5_creds));
      if (krb5_cache_state->creds2 == NULL)
	{
	  debug ("<== __nss_ldap_krb5_cache_renew: out of memory failed to allocate creds2");
	  return 1;
	}
      memset(krb5_cache_state->creds2, 0, sizeof(krb5_creds));
    }
  assert(krb5_cache_state->cc != NULL);

  debug (":== __nss_ldap_krb5_cache_renew: call krb5_cc_get_principal");

  code = krb5_cc_get_principal (krb5_cache_state->context, krb5_cache_state->cc, &(krb5_cache_state->creds2.client));

  debug (":== __nss_ldap_krb5_cache_renew: krb5_cc_get_principal returns %d", code);

  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_renew: %s(%d) while getting principal from credentials cache",
	 error_message (code), (int) code);
      krb5_cache_state->cache_state = KRB5_CACHE_REFRESH;
      return code;
    }

  debug (":== __nss_ldap_krb5_cache_renew: call krb5_princ_realm");

  client_realm = krb5_princ_realm (krb5_cache_state->context, krb5_cache_state->creds2.client);

  debug (":== __nss_ldap_krb5_cache_renew: krb5_princ_realm returned %p, call krb5_make_principal");

  code = krb5_make_principal (krb5_cache_state->context, &(krb5_cache_state->creds2.server), *client_realm,
			      KRB5_TGS_NAME, *client_realm, NULL);

  debug (":== __nss_ldap_krb5_cache_renew: krb5_make_principal returns %d", code);
  if (code != 0)
    {
      debug ("<== krb5_cache_renew: %s(%d) while getting krbtgt principal",
	     error_message (code), (int) code);
      krb5_cache_state->cache_state = KRB5_CACHE_REFRESH;
      return code;
    }

  /* I think there is a potential storage leak here as creds is written to */
  /* Need to check Heimdal code to see if it will overwrite or replace memory */
  debug (":== __nss_ldap_krb5_cache_renew: call krb5_get_kdc_cred");

  code = krb5_get_kdc_cred (krb5_cache_state->context,
			    krb5_cache_state->cc, flags, NULL,
			    NULL, krb5_cache_state->creds2,
			    &krb5_cache_state->creds);

  debug (":== __nss_ldap_krb5_cache_renew: krb5_get_kdc_cred returned %d");

  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_renew: failed to get creds from kdc %s(%d)",
	     error_message (code), (int) code);
#endif
      if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
	{
	  /* this can happen because of clock skew */
	  debug ("<== __nss_ldap_krb5_cache_renew: ticket has expired because of clock skew --> EXPIRED");
	  krb5_cache_state->cache_state = KRB5_CACHE_EXPIRED;
	  return 0;
	}
      else
	{
	  debug ("==> __nss_ldap_krb5_cache_renew: %s(%d) while renewing credentials",
		 error_message (code), (int) code);
	  krb5_cache_state->cache_state = KRB5_CACHE_REFRESH;
	  return code;
	}
    }
  krb5_cache_state->cache_state = KRB5_CACHE_RUNNING;

  debug ("<== __nss_ldap_krb5_cache_renew: renewed creds --> RUNNING");

  return 0;
}

/* Initialise the credentials cache from a keytab */
static int
__nss_ldap_krb5_cache_acquire (_nss_ldap_krb5_state_p krb5_cache_state, ldap_config_t *config)
{

  krb5_error_code code;
  krb5_keytab keytab = NULL;
  krb5_get_init_creds_opt options;
  krb5_deltat rlife;
  int usekeytab;

  debug ("==> __nss_ldap_krb5_cache_acquire");
  /*
   * We have not managed to find any credentials.
   * If a keytab is configured then try using that
   */
  assert (krb5_cache_state != NULL);
  assert (config != NULL);
  assert (krb5_cache_state->context != NULL);

  /* use keytab to fill cache */

  usekeytab = config->ldc_krb5_usekeytab ||
      (krb5_cache_state->euid == 0 && config->ldc_krb5_rootusekeytab);
  if (!usekeytab || krb5_cache_state->ktname == NULL)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: no usable keytab");
      code = ENOENT;
      goto finish_acquire_creds;
    }

  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_kt_resolve");

  code = krb5_kt_resolve (krb5_cache_state->context, krb5_cache_state->ktname, &keytab);

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_kt_resolve returns %d", code);

  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: %s(%d) while resolving keytab filename %s",
	     error_message (code), (int) code, krb5_cache_state->ktname);
      goto finish_acquire_creds;
    }

  if (krb5_cache_state->saslid == NULL)
    {
      krb5_cache_state->saslid = __nss_ldap_krb5_cache_get_saslid (krb5_cache_state, config);
    }

  debug (":== __nss_ldap_krb5_cache_acquire: saslid = %s",
	 (krb5_cache_state->saslid) ? krb5_cache_state->saslid : "NULL");

  if (krb5_cache_state->saslid && krb5_cache_state->principal == NULL)
    {
      krb5_cache_state->principal = __nss_ldap_krb5_cache_get_principal (krb5_cache_state);
      if (krb5_cache_state->principal == NULL)
	{
	  debug ("<== __nss_ldap_krb5_cache_acquire: no valid principal --> ERROR");
	  code = ENOENT;
	  goto finish_acquire_creds;
	}
    }

  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_get_init_creds_opt_init");

  krb5_get_init_creds_opt_init (&options);

  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_string_to_deltat");

  code = krb5_string_to_deltat (MAX_RENEW_TIME, &rlife);

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_string_to_deltat returns %d", code);
  if (code != 0 || rlife == 0)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: %s(%d) while setting renew lifetime value to %s",
	     error_message (code), (int) code, MAX_RENEW_TIME);
      code = (code == 0) ? 1 : code;
      goto finish_acquire_creds;
    }

  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_get_init_creds_opt_set_renew_life");

  krb5_get_init_creds_opt_set_renew_life (&options, rlife);

  debug (":== __nss_ldap_krb5_cache_acquire: get credentials from keytab");

  code = __nss_ldap_krb5_cache_setup_creds (krb5_cache_state);
  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_acquire: failed to set up credentials");
      goto finish_acquire_creds;
    }

  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_get_init_creds_keytab");

  code = krb5_get_init_creds_keytab (krb5_cache_state->context,
				     krb5_cache_state->creds,
				     krb5_cache_state->principal,
				     keytab,
				     0,
				     NULL,
				     &options);

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_get_init_creds_keytab returns %d", code);

  if (code != 0 && code != EEXIST)
    {
      /* Failed to initialise credentials from keytab */
      debug (":== __nss_ldap_krb5_cache_acquire get credentials from keytab failed %s(%d)",
	     error_message (code), (int) code);
      debug (":== __nss_ldap_krb5_cache_acquire try refreshing from credential cache");
      code = __nss_ldap_krb5_cache_refresh (krb5_cache_state);
      if (code != 0)
	{
	  debug (":== __nss_ldap_krb5_cache_acquire: cache credentials not usable");
	  free (krb5_cache_state->creds);
	  krb5_cache_state->creds = NULL;
	}
      else if (krb5_cache_state->cache_state == KRB5_CACHE_ACQUIRE)
	code = EEXIST;
      goto finish_acquire_creds;
    }

  /* We have a set of credentials we now need to save them */
  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_cc_resolve");

  code = krb5_cc_resolve (krb5_cache_state->context, krb5_cache_state->ccname, &(krb5_cache_state->cc));

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_cc_resolve returns %d", code);

  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: %s(%d) while resolving credential cache",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }
  
  debug (":== __nss_ldap_krb5_cache_acquire: call krb5_cc_initialize");

  code = krb5_cc_initialize (krb5_cache_state->context, krb5_cache_state->cc, krb5_cache_state->principal);

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_cc_initialize returns %d", code);

  if (code != 0 && code != EEXIST)
    {
      /* Failed to initialize the cache try to use a default one instead */
      debug (":== __nss_ldap_krb5_cache_acquire: initializing credential cache failed %s(%d)",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }

  debug (":== __nss_ldap_krb5_cache_acquire call krb5_cc_store_cred");

  code = krb5_cc_store_cred (krb5_cache_state->context, krb5_cache_state->cc, krb5_cache_state->creds);

  debug (":== __nss_ldap_krb5_cache_acquire: krb5_cc_store_cred returns %d", code);

  if (code != 0)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: %s(%d) while storing credentials",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }

  if (krb5_cache_state->creds->times.starttime == 0)
    krb5_cache_state->creds->times.starttime = krb5_cache_state->creds->times.authtime;

  debug (":== __nss_ldap_krb5_cache_acquire: got new credentials");
  krb5_cache_state->cache_state = KRB5_CACHE_RUNNING;

  code = 0;

 finish_acquire_creds:

  if (krb5_cache_state->cc != NULL)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: call krb5_cc_close");

      code = krb5_cc_close (krb5_cache_state->context, krb5_cache_state->cc);

      krb5_cache_state->cc = NULL;

      debug (":== __nss_ldap_krb5_cache_acquire: krb5_cc_close returns %d", code);

      if (code != 0)
	{
	  debug (":== __nss_ldap_krb5_cache_acquire: cache %s close failed",
		 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL");
	}
    }
 
  if (keytab != NULL)
    {
      debug (":== __nss_ldap_krb5_cache_acquire: call krb5_kt_close");

      code = krb5_kt_close (krb5_cache_state->context, keytab);

      debug (":== __nss_ldap_krb5_cache_acquire: krb5_kt_close returns %d", code);
    }

  if (code != 0)
    {
      debug ("<== __nss_ldap_krb5_cache_acquire: --> ERROR");
      krb5_cache_state->cache_state = KRB5_CACHE_ERROR;
    }
  else
    {
      debug ("<== __nss_ldap_krb5_cache_acquire");
    }

  return code;
}

/*
 * Entry points into the kerberos support
 */
static void *
__nss_ldap_krb5_cache_init (ldap_session_t *session)
{
  krb5_error_code code;
  ldap_session_opaque_t krb5_cache_state_obj = NULL;
  _nss_ldap_krb5_state_p krb5_cache_state = NULL;
  ldap_config_t * config = NULL;
  uid_t euid = geteuid();

  debug ("==> __nss_ldap_krb5_cache_init");

  if (session == NULL)
    {
      debug ("<== __nss_ldap_krb5_cache_init: called with NULL session ignoring krb5 initialisation");
      return NULL;
    }

  config = session->ls_config;

  if (config == NULL)
    {
      debug("<== __nss_ldap_krb5_cache_init: no configuration available ignoring krb5 initialisation");
      return NULL;
    }

  debug (":== __nss_ldap_krb5_cache_init: keytabname = %s, ccname = %s, saslid = %s, rootkeytabname = %s, rootccname = %s, rootsaslid = %s",
	 config->ldc_krb5_keytabname ? config->ldc_krb5_keytabname : "NULL",
	 config->ldc_krb5_ccname ? config->ldc_krb5_ccname : "NULL",
	 config->ldc_saslid ? config->ldc_saslid : "NULL",
	 config->ldc_krb5_rootkeytabname ? config->ldc_krb5_rootkeytabname : "NULL",
	 config->ldc_krb5_rootccname ? config->ldc_krb5_rootccname : "NULL",
	 config->ldc_rootsaslid ? config->ldc_rootsaslid : "NULL");

  /*
   * Check to see if we are using sasl, if not then return as nothing to do
   * This is a guard as we would not expect to be called unless sasl is running
   */
  if (!(config->ldc_usesasl || (euid == 0 && config->ldc_rootusesasl)))
    {
      return NULL;
    }

  krb5_cache_state_obj = __nss_ldap_find_opaque(session, LSO_KRB5);

  if (krb5_cache_state_obj == NULL)
    {
      krb5_cache_state_obj = __nss_ldap_allocate_opaque(session, LSO_KRB5);
      if (krb5_cache_state_obj == NULL)
	{
	  debug ("<== __nss_ldap_krb5_cache_init - out of memory while allocating state object container");
	  return NULL;
	}
    }
  if ((krb5_cache_state = krb5_cache_state_obj->lso_data) == NULL)
    {
      krb5_cache_state = krb5_cache_state_obj->lso_data = (_nss_ldap_krb5_state_p)malloc(sizeof(_nss_ldap_krb5_state));
      if (krb5_cache_state == NULL)
	{
	  __nss_ldap_free_opaque(session, LSO_KRB5);
	  debug ("<== __nss_ldap_krb5_cache_init - out of memory while allocating state object");
	  return NULL;
	}
      memset((void*)krb5_cache_state, 0, sizeof(_nss_ldap_krb5_state));
      krb5_cache_state->euid = -1; /* force reset */
    }

  /* Check to see if we have swapped user since we were last called */
  if (krb5_cache_state->euid != euid)
    { /* Could be first call but clear everything out anyway */
      __nss_ldap_krb5_cache_reset (krb5_cache_state);
      krb5_cache_state->euid = euid;
    }

  /* 
   * If we do not have any credentials
   * or they are expired or they are about to expire
   * then try to load a new set from the credentials cache
   * - this may have been renewed by
   * some other process or thread so check this first.
   */
  do
    {
      switch (krb5_cache_state->cache_state)
	{

	case KRB5_CACHE_INIT:
	  code = __nss_ldap_krb5_cache_setup (krb5_cache_state, config);
	  debug (":== __nss_ldap_krb5_cache_init: ktname = %s, ccname = %s, saslid = %s, euid = %d",
		 krb5_cache_state->ktname ? krb5_cache_state->ktname : "NULL",
		 krb5_cache_state->ccname ? krb5_cache_state->ccname : "NULL",
		 krb5_cache_state->saslid ? krb5_cache_state->saslid : "NULL",
		 krb5_cache_state->euid);
	  break;

	case KRB5_CACHE_RUNNING:
	  /*
	   * If we have credentials 
	   * and they are not expired or about to expire then OK!
	   */
	  if (credsOK (krb5_cache_state))
	    {
	      debug ("<== __nss_ldap_krb5_cache_init: return OK");
	      return krb5_cache_state;
	    }

	  if (credsEXPIRED (krb5_cache_state))
	    {
	      krb5_cache_state->cache_state = KRB5_CACHE_EXPIRED;
	    }
	  else if (credsEXPIRING (krb5_cache_state))
	    {
	      krb5_cache_state->cache_state = KRB5_CACHE_REFRESH;
	    }
	  else
	    {
	      /* Should not get here if things are OK so start again */
	      debug(":== __nss_ldap_krb5_cache_init: RESET credentials as we got into an unusual state");
	      __nss_ldap_krb5_cache_reset (krb5_cache_state);
	      krb5_cache_state->cache_state = KRB5_CACHE_INIT;
	    }
	  break;

	case KRB5_CACHE_RENEW:
	  debug(":== __nss_ldap_krb5_cache_init: RENEW credentials");
	  code = __nss_ldap_krb5_cache_renew (krb5_cache_state);
	  break;

	case KRB5_CACHE_EXPIRED:
	  debug(":== __nss_ldap_krb5_cache_init: ACQUIRE credentials they EXPIRED");
	  code = __nss_ldap_krb5_cache_acquire (krb5_cache_state, config);
	  break;

	case KRB5_CACHE_REFRESH:
	  debug(":== __nss_ldap_krb5_cache_init: REFRESH credentials");
	  code = __nss_ldap_krb5_cache_refresh (krb5_cache_state);
	  break;

	case KRB5_CACHE_ACQUIRE:
	  debug(":== __nss_ldap_krb5_cache_init: ACQUIRE credentials  first time");
	  code = __nss_ldap_krb5_cache_acquire (krb5_cache_state, config);
	  break;

	case KRB5_CACHE_ERROR:
	  /*
	   * Can't do anything while in ERROR state.
	   * So release all of the structures and return failure, let the higher level code try again later.
	   */
	  __nss_ldap_krb5_cache_close(session);
	  debug(":== __nss_ldap_krb5_cache_init: reset cache for ERROR state");
	  code = -1;
	  break;

	default:
	  debug(":== __nss_ldap_krb5_cache_init: got a default entry for state %d this is an error",
		krb5_cache_state->cache_state);
	  break;
	}
      if (code != 0)
	{
	  debug ("<== krb5_cache_init: got %d", (int) code);
	  return krb5_cache_state;
	}
    }
  while (1);

  /*NOTREACHED*/
  debug ("<== krb5_cache_init: reinit ticket loop exit failure");

  return krb5_cache_state;
}

static int
__nss_ldap_krb5_cache_select (ldap_session_t *session)
{
  int result = 0;
  ldap_session_opaque_t krb5_cache_state_obj = NULL;
  _nss_ldap_krb5_state_p krb5_cache_state = NULL;

  debug("==> __nss_ldap_krb5_cache_select");

  if (session == NULL)
    {
      debug ("<== __nss_ldap_krb5_cache_select: called with NULL session cache not running");
      return -1;
    }

  krb5_cache_state_obj = __nss_ldap_find_opaque(session, LSO_KRB5);

  if (krb5_cache_state_obj == NULL)
    {
      krb5_cache_state = (_nss_ldap_krb5_state_p)__nss_ldap_krb5_cache_init (session);
    }
  else 
    {
      krb5_cache_state = (_nss_ldap_krb5_state_p)(krb5_cache_state_obj->lso_data);
    }
  if (krb5_cache_state == NULL)
    {
    debug ("<== __nss_ldap_krb5_cache_select - cache initialisation failed no state object allocated");
    return -1;
    }
  if (krb5_cache_state->cache_state != KRB5_CACHE_RUNNING)
    {
    debug ("<== __nss_ldap_krb5_cache_select - cache initialisation failed - cache not running");
    return -1;
    }
  if (krb5_cache_state->ccname != NULL)
    {
      OM_uint32 retval = 0;
      krb5_error_code code;

      debug (":== __nss_ldap_krb5_cache_select: call gss_krb5_ccache_name");

      code = gss_krb5_ccache_name (&retval,
				   (const char *) krb5_cache_state->ccname,
				   (const char **) &(krb5_cache_state->saveccname));
      if (code != GSS_S_COMPLETE)
	{
	  debug (":== __nss_ldap_krb5_cache_select: unable to set default credential cache - retval %d", retval);
	  result = -1;
	}
      debug(":== __nss_ldap_krb5_cache_select: ccname = %s", krb5_cache_state->ccname);
    }
  else
    {
      debug(":== __nss_ldap_krb5_cache_select: ccname is NULL");
    }

  debug ("<== __nss_ldap_krb5_cache_select returns result = %d", result);

  return result;
}

static int
__nss_ldap_krb5_cache_restore (ldap_session_t *session)
{
  int result = 0;
  ldap_session_opaque_t krb5_cache_state_obj = NULL;
  _nss_ldap_krb5_state_p krb5_cache_state = NULL;
  OM_uint32 retval = 0;
  krb5_error_code code;

  debug("==> __nss_ldap_krb5_cache_restore");

  if (session == NULL)
    {
      debug ("<== __nss_ldap_krb5_cache_restore: called with NULL session cache not running");
      return -1;
    }

  krb5_cache_state_obj = __nss_ldap_find_opaque(session, LSO_KRB5);

  if (krb5_cache_state_obj == NULL)
    {
      debug ("<== __nss_ldap_krb5_cache_restore - cache not initialised no state object container allocated");
      return -1;
    }
  if ((krb5_cache_state = (_nss_ldap_krb5_state_p)(krb5_cache_state_obj->lso_data)) == NULL)
    {
      __nss_ldap_free_opaque(session, LSO_KRB5);
      debug ("<== __nss_ldap_krb5_cache_restore - cache not initialised no state object allocated");
      return -1;
    }
  if (krb5_cache_state->cache_state != KRB5_CACHE_RUNNING)
    {
      debug ("<== __nss_ldap_krb5_cache_restore - cache not initialised - cache not running");
      return -1;
    }

  debug (":== __nss_ldap_krb5_cache_restore: call gss_krb5_ccache_name");

  code = gss_krb5_ccache_name (&retval, (const char *) krb5_cache_state->saveccname, NULL);
  if (code != GSS_S_COMPLETE)
    {
      debug (":== __nss_ldap_krb5_cache_restore: unable to restore default credential cache- retval %d", retval);
      result = -1;
    }

  krb5_cache_state->saveccname = NULL;

  debug ("<== __nss_ldap_krb5_cache_restore: returns result = %d", result);

  return result;
}

static void
__nss_ldap_krb5_cache_close (ldap_session_t *session)
{
  ldap_session_opaque_t krb5_cache_state_obj = NULL;
  _nss_ldap_krb5_state_p krb5_cache_state = NULL;

  debug ("==> __nss_ldap_krb5_cache_close");

  if (session == NULL)
    {
      debug ("<== __nss_ldap_krb5_cache_close: called with NULL session cache not running");
      return;
    }

  krb5_cache_state_obj = __nss_ldap_find_opaque(session, LSO_KRB5);

  if (krb5_cache_state_obj != NULL
      && (krb5_cache_state = (_nss_ldap_krb5_state_p)(krb5_cache_state_obj->lso_data)) != NULL)
    {
      __nss_ldap_krb5_cache_reset(krb5_cache_state);
    }

  __nss_ldap_free_opaque(session, LSO_KRB5);

  debug ("<== __nss_ldap_krb5_cache_close");

  return;
}

#endif  /*  defined(CONFIGURE_KRB5_KEYTAB) */

#if defined(CONFIGURE_KRB5_CCNAME)

static const char *saveccname = NULL;
# if defined(CONFIGURE_KRB5_CCNAME_ENV)
static char envbuf[256];
#endif

static void
__nss_ldap_krb5_cache_init (ldap_session_t * session)
{
  return;
}

static int
__nss_ldap_krb5_cache_select (ldap_session_t * session)
{
  char *ccname;
# if defined(CONFIGURE_KRB5_CCNAME_ENV)
  char tmpbuf[256];
# elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
  int retval;
# endif

  /* Set default Kerberos ticket cache for SASL-GSSAPI */
  /* There are probably race conditions here XXX */
  ccname = session->ls_config->ldc_krb5_ccname;
  if (ccname != NULL)
    {
      char *ccfile = ccname;
      /* If the cache is a file then we need to be able to read it */
      if (strncasecmp(ccfile, "MEMORY:", sizeof("MEMORY:") - 1) != 0)
	{
	  /* Check that cache exists and is readable */
	  if ((strncasecmp(ccfile, "FILE:", sizeof("FILE:") - 1) == 0)
	      || (strncasecmp(ccfile, "WRFILE:", sizeof("WRFILE:") - 1) == 0))
	    {
	      ccfile = strchr(ccfile, ':') + 1;
	    }
	}
    }
  if (ccname != NULL)
    {
# if defined(CONFIGURE_KRB5_CCNAME_ENV)
      saveccname = getenv ("KRB5CCNAME");
      if (saveccname != NULL)
	{
	  strncpy (tmpbuf, saveccname, sizeof (tmpbuf));
	  tmpbuf[sizeof (tmpbuf) - 1] = '\0';
	}
      else
	{
	  tmpbuf[0] = '\0';
	}
      saveccname = strdup(tmpbuf);
      snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", ccname);
      putenv (envbuf);
# elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
      if (gss_krb5_ccache_name (&retval, ccname, &saveccname) != GSS_S_COMPLETE)
	{
	  debug ("krb5_cache_select: unable to set default credential cache");
	  return -1;
	}
      saveccname = strdup(saveccname);
# endif
    }
  return 0;
}

static int
__nss_ldap_krb5_cache_restore (ldap_session_t *session)
{
# if defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
  int retval;
#endif
  /* Restore default Kerberos ticket cache. */
  if (saveccname != NULL)
    {
# if defined(CONFIGURE_KRB5_CCNAME_ENV)
      snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", saveccname);
      putenv (envbuf);
# elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
      if (gss_krb5_ccache_name (&retval, saveccname, NULL) != GSS_S_COMPLETE)
	{
	  debug ("krb5_cache_restore: unable to restore default credential cache");
	  return -1;
	}
# endif
      free(saveccname);
      saveccname = NULL;
    }
  return 0;
}

static void
__nss_ldap_krb5_cache_close (ldap_session_t *session)
{
  return;
}

#endif /*  defined(CONFIGURE_KRB5_CCNAME) */

#if !defined(CONFIGURE_KRB5_KEYTAB) && !defined(CONFIGURE_KRB5_CCNAME)
static void *
__nss_ldap_krb5_cache_init (ldap_session_t *session)
{
  return NULL;
}

static int
__nss_ldap_krb5_cache_select (ldap_session_t *session)
{
  return 0;
}

static int
__nss_ldap_krb5_cache_restore (ldap_session_t *session)
{
  return 0;
}

static void
__nss_ldap_krb5_cache_close (ldap_session_t *session)
{
  return;
}

#endif /* !defined(CONFIGURE_KRB5_KEYTAB) && !defined(CONFIGURE_KRB5_CCNAME) */

ldap_session_mech_t
__nss_ldap_krb5_cache(void)
{
  ldap_session_mech_t krb5_cache_mech = NULL;

  debug("==> __nss_ldap_krb5_cache");

  krb5_cache_mech = __nss_ldap_mech_setup(LSM_KRB5,
					  __nss_ldap_krb5_cache_init,
					  __nss_ldap_krb5_cache_select,
					  __nss_ldap_krb5_cache_restore,
					  __nss_ldap_krb5_cache_close);

  if (krb5_cache_mech == NULL)
    {
      debug (":== __nss_ldap_krb5_cache: Failed to allocate mech structure for kerberos mechs");
    }

  debug ("<== __nss_ldap_krb5_cache: return %p", krb5_cache_mech);

  return krb5_cache_mech;
}

