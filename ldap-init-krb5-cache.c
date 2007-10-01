/* Copyright (C) 2007 Howard Wilkinson
   Copyright (C) 2007 Markus Moeller
   Copyright (C) 2007 Luke Howard
   This file is part of the nss_ldap library
   Contributed by Howard Wilkinson <howard@cohtech.com>, 2007.

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
 * This file implementes the management of the Kerberos Credential Cache
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
 *				Try for a keytab if one if configured
 * ACQUIRE:	No credentials loaded acquire new ones - (See EXPIRED)
 * ERROR:	Call reset and then return failure from this attempt
 *		 => REFRESH
 */

/*
 * The code is written to allow and external program to supply credentials
 * in the environment. This program can refresh/renew the credentials
 * periodically and we will use these.
 * As an alternative this code can renew externally provided credentials
 * if necessary - autorenew must be turned on.
 * Finally if provided with a keytab this code will acquire credentials
 * from a KDC
 */

/*
 * 31st July 2007 -	 NO ATTEMPT HAS BEEN MADE TO MAKE
 *			 THIS CODE THREAD SAFE AT THIS TIME
 */

#include "config.h"
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#include "ldap-nss.h"
#ifdef CONFIGURE_KRB5_KEYTAB
#include <krb5.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#ifndef HEIMDAL
#include <profile.h>
#endif
#ifdef HEIMDAL
#define error_message(code) krb5_get_err_text(context,code)
#endif
#include <sys/types.h>
#include <assert.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#define MAX_RENEW_TIME "365d"

#define KT_PATH_MAX 256

#ifndef HEIMDAL
typedef struct _profile_t *profile_t;
#endif

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

/* Run the state machine from here */
static krb5_cache_state cache_state = KRB5_CACHE_INIT;

/* Track our Effective UID incase it is changing as we run */
static uid_t __euid = -1;
static uid_t euid = -1;

static krb5_context context = NULL;
static krb5_creds *creds = NULL;
#ifdef HEIMDAL
static krb5_creds creds2;
#endif
static krb5_principal principal = NULL;
static krb5_ccache cc = NULL;
static krb5_deltat skew = 0;
static char *ccname = NULL;
static char *ktname = NULL;
static char *saslid = NULL;
static int autorenew = 0;

#define credsOK(__c__) \
  ((__c__ != NULL) && ((__c__->times.endtime - time(0)) > (2*skew)))

#define credsEXPIRING(__c__) \
  ((__c__ != NULL) \
   && (((__c__->times.endtime - time(0)) <= (2*skew)) \
       && ((__c__->times.endtime - time(0)) > skew)))

#define credsEXPIRED(__c__) \
  ((__c__ == NULL) \
   || (((__c__->times.renew_till - time(0)) <= (2*skew)) \
       || ((__c__->times.endtime - time(0)) <= skew)))

static int
krb5_cache_reset (ldap_config_t * config)
{
  debug ("==> krb5_cache_reset");
  if (creds != NULL)
    {
      free ((void *) creds);
      creds = NULL;
    }
  if (context != NULL)
    {
      if (principal != NULL)
	{
	  krb5_free_principal (context, principal);
	  principal = NULL;
	}
      if (cc != NULL)
	{
	  krb5_cc_close (context, cc);
	  cc = NULL;
	}
      krb5_free_context (context);
      context = NULL;
    }
  skew = 0;
  autorenew = 0;
  if (ccname != NULL)
    {
      free ((void *) ccname);
      ccname = NULL;
    }
  if (ktname != NULL)
    {
      free ((void *) ktname);
      ktname = NULL;
    }
  if (saslid != NULL)
    {
      free ((void *) saslid);
      saslid = NULL;
    }
  cache_state = KRB5_CACHE_INIT;
  debug ("<== krb5_cache_reset");
  return (0);
}

static int
krb5_cache_kt_is_accessible (char *__ktname)
{
  krb5_error_code code = 0;
  krb5_keytab __keytab;

  debug ("==> krb5_cache_kt_is_accessible: ktname %s", __ktname);
  assert (context != NULL);
  if (!(code = krb5_kt_resolve (context, __ktname, &__keytab)))
    {
      debug ("==> krb5_cache_kt_is_accessible: resolved ktname %s - %s",
	     __ktname, krb5_kt_get_type (context, __keytab));
      if (strcmp ("FILE", krb5_kt_get_type (context, __keytab)) == 0)
	{
	  debug ("==> krb5_cache_kt_is_accessible: kt type = FILE");
	  uid_t ruid = getuid ();
	  gid_t rgid = getgid ();
	  gid_t egid = getegid ();
	  char buf[KT_PATH_MAX];
	  if (ruid != euid)
	    {
	      setreuid (euid, ruid);
	    }
	  if (rgid != egid)
	    {
	      setregid (egid, rgid);
	    }
	  krb5_kt_get_name (context, __keytab, buf, KT_PATH_MAX);
	  debug ("==> krb5_cache_kt_is_accessible: kt_get_name gives %s",
		 buf);
	  code = access (buf, R_OK);
	  if (ruid != euid)
	    {
	      setreuid (ruid, euid);
	    }
	  if (rgid != rgid)
	    {
	      setregid (rgid, egid);
	    }
	}
      krb5_kt_close (context, __keytab);
    }

  debug ("<== krb5_cache_kt_is_accessible: returns %s(%d)",
	 error_message (code), (int) code);
  return (code == 0);
}

static char *
krb5_cache_get_ktname (ldap_config_t * config)
{
  char *__ktname = NULL;

  debug ("==> krb5_cache_get_ktname");
  {
    char *rootktname = ((euid == 0 && config->ldc_krb5_rootusekeytab
			 && config->ldc_rootusesasl
			 && config->ldc_krb5_rootkeytabname)
			? config->ldc_krb5_rootkeytabname : NULL);
    char *userktname = ((((config->ldc_usesasl && config->ldc_krb5_usekeytab)
			  || (euid == 0 && config->ldc_rootusesasl
			      && config->ldc_krb5_rootusekeytab))
			 && config->ldc_krb5_keytabname)
			? config->ldc_krb5_keytabname : NULL);
    char *envktname = ((((config->ldc_usesasl && config->ldc_krb5_usekeytab)
			 || (euid == 0 && config->ldc_rootusesasl
			     && config->ldc_krb5_rootusekeytab))
			&& getenv ("KRB5_KTNAME"))
		       ? getenv ("KRB5_KTNAME") : NULL);
    char *defktname = NULL;

    if ((config->ldc_usesasl && config->ldc_krb5_usekeytab)
	|| (euid == 0 && config->ldc_rootusesasl
	    && config->ldc_krb5_rootusekeytab))
      {
	char buf[KT_PATH_MAX];
	debug ("==> krb5_cache_get_ktname: get default keytab name");
	krb5_kt_default_name (context, buf, KT_PATH_MAX);
	defktname = strdup (buf);
      }

    debug
      ("==> krb5_cache_get_ktname: rootktname = %s, userktname = %s, envktname = %s, defktname = %s",
       (rootktname) ? rootktname : "NULL", (userktname) ? userktname : "NULL",
       (envktname) ? envktname : "NULL", (defktname) ? defktname : "NULL");
    __ktname =
      ((rootktname
	&& krb5_cache_kt_is_accessible (rootktname)) ? rootktname
       : (userktname
	  && krb5_cache_kt_is_accessible (userktname)) ? userktname
       : (envktname
	  && krb5_cache_kt_is_accessible (envktname)) ? envktname : (defktname
								     &&
								     krb5_cache_kt_is_accessible
								     (defktname))
       ? defktname : NULL);
  }
  debug ("<== krb5_cache_get_ktname: returns %s",
	 (__ktname) ? __ktname : "NULL");
  return __ktname;
}

static int
krb5_cache_cc_is_accessible (char *__ccname, int writeable)
{
  krb5_error_code code = 0;
  krb5_ccache __cc;

  debug ("==> krb5_cache_cc_is_accessible: ccname %s, writeable %d",
	 __ccname, writeable);
  assert (context != NULL);
  if (!(code = krb5_cc_resolve (context, __ccname, &__cc)))
    {
      debug ("==> krb5_cache_cc_is_accessible: resolved ccname %s - %s",
	     __ccname, krb5_cc_get_type (context, __cc));
      if ((strcmp ("FILE", krb5_cc_get_type (context, __cc)) == 0)
	  || (strcmp ("WRFILE", krb5_cc_get_type (context, __cc)) == 0))
	{
	  int mode = R_OK;
	  uid_t ruid = getuid ();
	  gid_t rgid = getgid ();
	  gid_t egid = getegid ();
	  if (writeable)
	    {
	      mode = mode | W_OK;
	    }
	  if (ruid != euid)
	    {
	      setreuid (euid, ruid);
	    }
	  if (rgid != egid)
	    {
	      setregid (egid, rgid);
	    }
	  if ((code = access (krb5_cc_get_name (context, __cc), F_OK)))
	    {
	      debug
		("==> krb5_cache_cc_is_accessible: cache file not accessible %s(%d)",
		 strerror (errno), errno);
	      if (errno == EACCES)
		{		/* File does not exist */
		  if (writeable)
		    {
		      /* Check that path exists */
		      char *x__ccname =
			strdup (krb5_cc_get_name (context, cc));
		      char *x__ccdir = dirname (x__ccname);
		      code = access (x__ccdir, mode | X_OK);
		      free ((void *) x__ccname);
		    }
		}
	    }
	  else
	    {
	      code = access (krb5_cc_get_name (context, __cc), mode);
	    }
	  if (ruid != euid)
	    {
	      setreuid (ruid, euid);
	    }
	  if (rgid != rgid)
	    {
	      setregid (rgid, egid);
	    }
	}
      krb5_cc_close (context, __cc);
    }

  debug ("<== krb5_cache_cc_is_accessible: returns %s(%d)",
	 error_message (code), code);
  return (code == 0);
}

static char *
krb5_cache_get_ccname (ldap_config_t * config)
{
  char *__ccname = NULL;

  debug ("==> krb5_cache_get_ccname");
  {
    char *rootccname = ((euid == 0
			 && config->ldc_rootusesasl
			 && config->ldc_krb5_rootccname)
			? config->ldc_krb5_rootccname : NULL);
    char *userccname = (((config->ldc_usesasl
			  || (euid == 0 && config->ldc_rootusesasl))
			 && config->ldc_krb5_ccname)
			? config->ldc_krb5_ccname : NULL);
    char *envccname = (((config->ldc_usesasl
			 || (euid == 0 && config->ldc_rootusesasl))
			&& getenv ("KRB5CCNAME"))
		       ? getenv ("KRB5CCNAME") : NULL);
    char *defccname = (((config->ldc_usesasl
			 || (euid == 0 && config->ldc_rootusesasl))
			&& (char *) krb5_cc_default_name (context))
		       ? (char *) krb5_cc_default_name (context) : NULL);

    int writeable = (autorenew
		     || config->ldc_krb5_usekeytab
		     || (euid == 0 && config->ldc_krb5_rootusekeytab));

    debug
      ("==> krb5_cache_get_ccname: rootccname = %s, userccname = %s, envccname = %s, defccname = %s",
       (rootccname) ? rootccname : "NULL", (userccname) ? userccname : "NULL",
       (envccname) ? envccname : "NULL", (defccname) ? defccname : "NULL");
    __ccname =
      ((rootccname
	&& krb5_cache_cc_is_accessible (rootccname,
					writeable)) ? rootccname : (userccname
								    &&
								    krb5_cache_cc_is_accessible
								    (userccname,
								     writeable))
       ? userccname : (envccname
		       && krb5_cache_cc_is_accessible (envccname,
						       writeable)) ? envccname
       : (defccname
	  && krb5_cache_cc_is_accessible (defccname,
					  writeable)) ? defccname : NULL);
    if (__ccname == NULL
	&& (config->ldc_krb5_usekeytab
	    || (euid == 0 && config->ldc_krb5_rootusekeytab)))
      __ccname = "MEMORY:store_creds";
  }
  debug ("<== krb5_cache_get_ccname: returns ccname = %s",
	 (__ccname) ? __ccname : "NULL");
  return ((__ccname) ? strdup (__ccname) : "NULL");
}

static char *
krb5_cache_get_saslid (ldap_config_t * config)
{
  char *__saslid = ((euid = 0 && config->ldc_rootusesasl
		     && config->ldc_rootsaslid)
		    ? config->ldc_rootsaslid
		    : (config->ldc_usesasl && config->ldc_saslid)
		    ? config->ldc_saslid : NULL);
  if (__saslid == NULL)
    {
      int retval;
      char hostname[HOST_NAME_MAX];

      debug ("==> krb5_cache_get_saslid: get default principal name");
      errno = 0;
      retval = gethostname (hostname, HOST_NAME_MAX);
      if (!retval)
	{
	  hostname[HOST_NAME_MAX] = '\0';
	  __saslid = malloc (sizeof (hostname) + 6);
	  strcpy (__saslid, "host/");
	  strcat (__saslid, hostname);
	  debug ("==> krb5_cache_get_saslid: set principal name %s",
		 __saslid);
	}
      else
	{
	  syslog (LOG_ERR, "nss_ldap: %s while resolving hostname",
		  strerror (errno));
	  debug ("==> krb5_cache_get_saslid: %s while resolving hostname",
		 strerror (errno));
	}
    }
  else
    {
      __saslid = strdup (__saslid);
    }
  return __saslid;
}

static krb5_principal
krb5_cache_get_principal (ldap_config_t * config)
{
  krb5_error_code code = 0;
  krb5_principal __principal;

  assert (saslid != NULL);
  if ((code = krb5_parse_name (context, saslid, &__principal)))
    {
      syslog (LOG_ERR, "nss_ldap: %s(%d) while parsing principal name %s",
	      error_message (code), (int) code, saslid);
      debug
	("==> krb5_cache_get_principal: %s(%d) while parsing principal name %s",
	 error_message (code), (int) code, saslid);
      return (NULL);
    }
  return __principal;
}

/* Set up to manage the credentials cache */
static int
krb5_cache_setup (ldap_config_t * config)
{

  krb5_error_code code = 0;

#ifndef HEIMDAL
  profile_t profile;
#endif

  debug ("==> krb5_cache_setup");
  if (context == NULL)
    {
      if ((code = krb5_init_context (&context)))
	{
	  syslog (LOG_ERR,
		  "nss_ldap: %s(%d) while initialising Kerberos library",
		  error_message (code), (int) code);
	  debug
	    ("<== krb5_cache_setup: %s(%d) while initialising Kerberos library",
	     error_message (code), (int) code);
	  return (code);
	}
    }
#ifndef HEIMDAL
  if ((code = krb5_get_profile (context, &profile)))
    {
      syslog (LOG_ERR, "nss_ldap: %s(%d) while getting profile",
	      error_message (code), (int) code);
      debug ("<== krb5_cache_setup: %s(%d) while getting profile",
	     error_message (code), (int) code);
      return (code);
    }
  if ((code = profile_get_integer (profile,
				   "libdefaults",
				   "clockskew", 0, 5 * 60, &skew)))
    {
      syslog (LOG_ERR, "nss_ldap: %s(%d) while getting clockskew",
	      error_message (code), (int) code);
      debug ("<== krb5_cache_setup: %s(%d) while getting clockskew",
	     error_message (code), (int) code);
      return (code);
    }
  profile_release (profile);
#else
  skew = context->max_skew;
#endif
  ccname = krb5_cache_get_ccname (config);
  debug ("==> krb5_cache_setup: credential cache name %s",
	 ccname ? ccname : "NULL");
  cache_state = KRB5_CACHE_REFRESH;
  autorenew = (config->ldc_krb5_autorenew
	       || (euid == 0 && config->ldc_krb5_rootautorenew));
  debug ("<== krb5_cache_setup");
  return (0);
}

static void
krb5_cache_setup_creds (ldap_config_t * context)
{
  debug ("==> krb5_cache_setup_creds");
  if (creds == NULL)
    {
      creds = malloc (sizeof (*creds));
      assert (creds != NULL);
    }
  memset (creds, 0, sizeof (*creds));
  debug ("<== krb5_cache_setup_creds");
}

/* (Re)load the credentials cache into our local data */
static int
krb5_cache_refresh (ldap_config_t * config)
{

  krb5_error_code code = 0;

  debug ("==> krb5_cache_refresh");
  if ((code = krb5_cc_resolve (context, ccname, &cc)))
    {
      debug ("==> krb5_cache_refresh: cache %s cannot be resolved",
	     ccname ? ccname : "NULL");
    }
  else if ((code = krb5_cc_get_principal (context, cc, &principal)))
    {
      debug ("==> krb5_cache_refresh: cannot get principal from cache %s",
	     ccname ? ccname : "NULL");
    }
  else
    {
      debug ("==> krb5_cache_refresh: found existing cache %s",
	     ccname ? ccname : "NULL");
      /* Use the principal name from the cache rather than preconfigured saslid */
      char *principal_name = NULL;
      if ((code = krb5_unparse_name (context, principal, &principal_name)))
	{
	  debug
	    ("==> krb5_cache_refresh: cannot unparse principal from cache %s",
	     ccname ? ccname : "NULL");
	}
      else
	{
	  krb5_cc_cursor cursor;

	  debug ("==> krb5_cache_refresh: cache %s principal %s",
		 ccname ? ccname : "NULL",
		 principal_name ? principal_name : "NULL");
	  if ((code = krb5_cc_start_seq_get (context, cc, &cursor)))
	    {
	      debug
		("==> krb5_cache_refresh: cache %s credentials not usable",
		 ccname ? ccname : "NULL");
	    }
	  else
	    {
	      krb5_cache_setup_creds (config);
	      do
		{
		  if (!
		      (code =
		       krb5_cc_next_cred (context, cc, &cursor, creds)))
		    {
		      debug ("==> krb5_cache_refresh: retrieved creds");
		      if (credsOK (creds))
			{
			  debug
			    ("==> krb5_cache_refresh: creds are OK --> RUNNING");
			  /* Reloaded cache is fine */
			  cache_state = KRB5_CACHE_RUNNING;
			}
		      else
			{
			  if (credsEXPIRING (creds))
			    {
			      debug
				("==> krb5_cache_refresh: creds are EXPIRING");
			      /* Reloaded cache will expire shortly */
			      if (autorenew)
				{
				  debug ("==> krb5_cache_refresh: --> RENEW");
				  cache_state = KRB5_CACHE_RENEW;
				}
			      else
				{
				  debug
				    ("==> krb5_cache_refresh: --> EXPIRED");
				  cache_state = KRB5_CACHE_EXPIRED;
				}
			    }
			  else if (credsEXPIRED (creds))
			    {
			      debug
				("==> krb5_cache_refresh: creds have EXPIRED --> EXPIRED");
			      /* Reload cache has expired */
			      cache_state = KRB5_CACHE_EXPIRED;
			    }
			  else
			    {	/* Should never happen */
			      debug
				("==> krb5_cache_refresh: creds in weird state --> ERROR");
			      cache_state = KRB5_CACHE_ERROR;
			    }
			  krb5_free_cred_contents (context, creds);
			}
		    }
		}
	      while (!code && cache_state == KRB5_CACHE_REFRESH);
	      if ((code = krb5_cc_end_seq_get (context, cc, &cursor)))
		{
		  debug
		    ("==> krb5_cache_refresh: cache %s scan failed to end cleanly",
		     ccname ? ccname : "NULL");
		}
	    }
	  krb5_free_unparsed_name (context, principal_name);
	}
    }

  if (principal != NULL)
    {
      krb5_free_principal (context, principal);
      principal = NULL;
    }
  if (cc != NULL)
    {
      if ((code = krb5_cc_close (context, cc)))
	{
	  debug ("==> krb5_cache_refresh: cache %s close failed",
		 ccname ? ccname : "NULL");
	}
      cc = NULL;
    }
  if (cache_state == KRB5_CACHE_REFRESH)
    {
      debug ("==> krb5_cache_refresh: stuck in refresh --> ACQUIRE");
      cache_state = KRB5_CACHE_ACQUIRE;	/* Try for a keytab */
    }
  debug ("<== krb5_cache_refresh");
  return (code);
}

/* Renew an expired credentials cache */
static int
krb5_cache_renew (ldap_config_t * config)
{

  krb5_error_code code = 0;

#ifdef HEIMDAL
  krb5_kdc_flags flags;
  krb5_realm *client_realm;
#endif

  debug ("==> krb5_cache_renew");

  if (!autorenew)
    {
      /*
       * We should never get here
       * as the refresh code should only enter renew
       * if autorenew is true
       */
      debug
	("==> krb5_cache_renew: renew called with autorenew off --> ERROR");
      cache_state = KRB5_CACHE_ERROR;
      return (1);
    }

  assert (creds != NULL);	/* Refresh or acquire will have set this up */
#ifndef HEIMDAL
  /* renew ticket */
  /* Overwrites contents of creds no storage allocation happening */
  if ((code = krb5_get_renewed_creds (context, creds, principal, cc, NULL)))
    {
      debug ("==> krb5_cache_renew: failed to renew creds %s(%d)",
	     error_message (code), (int) code);
#else
  /* renew ticket */
  flags.i = 0;
  flags.b.renewable = flags.b.renew = 1;
  if ((code = krb5_cc_get_principal (context, cc, &creds2.client)))
    {
      syslog (LOG_ERR,
	      "nss_ldap: %s(%d) while getting principal from credential cache",
	      error_message (code), (int) code);
      debug
	("==> krb5_cache_renew: %s(%d) while getting principal from credentials cache",
	 error_message (code), (int) code);
      cache_state = KRB5_CACHE_REFRESH;
      return (code);
    }
  client_realm = krb5_princ_realm (context, creds2.client);
  if ((code = krb5_make_principal (context, &creds2.server, *client_realm,
				   KRB5_TGS_NAME, *client_realm, NULL)))
    {
      syslog (LOG_ERR, "nss_ldap: %s(%d) while getting krbtgt principal",
	      error_message (code), (int) code);
      debug ("==> krb5_cache_renew: %s(%d) while getting krbtgt principal",
	     error_message (code), (int) code);
      cache_state = KRB5_CACHE_REFRESH;
      return (code);
    }
  /* I think there is a potential storage leak here as creds is written to */
  /* Need to check Heimdal code to see if it will overwrite or replace memory */
  if ((code = krb5_get_kdc_cred (context,
				 cc, flags, NULL, NULL, &creds2, &creds)))
    {
      debug ("==> krb5_cache_renew: failed to get creds from kdc %s(%d)",
	     error_message (code), (int) code);
#endif
      if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
	{
	  /* this can happen because of clock skew */
	  debug
	    ("<== krb5_cache_renew: ticket has expired because of clock skey --> EXPIRED");
	  cache_state = KRB5_CACHE_EXPIRED;
	  return (0);
	}
      else
	{
	  syslog (LOG_ERR, "nss_ldap: %s(%d) while renewing credentials",
		  error_message (code), (int) code);
	  debug ("==> krb5_cache_renew: %s(%d) while renewing credentials",
		 error_message (code), (int) code);
	  cache_state = KRB5_CACHE_REFRESH;
	  return (code);
	}
    }
  cache_state = KRB5_CACHE_RUNNING;
  debug ("<== krb5_cache_renew: renewed creds --> RUNNING");
  return (0);
}

/* Initialise the credentials cache from a keytab */
static int
krb5_cache_acquire (ldap_config_t * config)
{

  krb5_error_code code = 0;
  krb5_keytab keytab = NULL;

  debug ("==> krb5_cache_acquire");
  /*
   * We have not managed to find any credentials.
   * If a keytab is configured then try using that
   */
  assert (context != NULL);
  /* use keytab to fill cache */
  if ((ktname == NULL) && ((ktname = krb5_cache_get_ktname (config)) == NULL))
    {
      debug ("==> krb5_cache_acquire: no usable keytab");
      code = 1;
    }
  else if ((code = krb5_kt_resolve (context, ktname, &keytab)))
    {
      syslog (LOG_ERR, "nss_ldap: %s(%d) while resolving keytab filename %s",
	      error_message (code), (int) code, ktname);
      debug
	("==> krb5_cache_acquire: %s(%d) while resolving keytab filename %s",
	 error_message (code), (int) code, ktname);
    }
  else
    {
      krb5_get_init_creds_opt options;
      krb5_deltat rlife;
      if (saslid == NULL)
	{
	  saslid = krb5_cache_get_saslid (config);
	}
      debug ("==> krb5_cache_acquire: saslid = %s",
	     (saslid) ? saslid : "NULL");
      if (saslid && principal == NULL)
	{
	  principal = krb5_cache_get_principal (config);
	  if (principal == NULL)
	    {
	      debug ("<== krb5_cache_acquire: no valid principal --> ERROR");
	      cache_state = KRB5_CACHE_ERROR;
	      return (1);
	    }
	}
      krb5_get_init_creds_opt_init (&options);
      if ((code = krb5_string_to_deltat (MAX_RENEW_TIME, &rlife))
	  || (rlife == 0))
	{
	  syslog (LOG_ERR,
		  "nss_ldap: %s(%d) while setting renew lifetime value to %s",
		  error_message (code), (int) code, MAX_RENEW_TIME);
	  debug
	    ("==> krb5_cache_acquire: %s(%d) while setting renew lifetime value to %s",
	     error_message (code), (int) code, MAX_RENEW_TIME);
	  code = (code == 0) ? 1 : code;
	}
      else
	{
	  krb5_get_init_creds_opt_set_renew_life (&options, rlife);
	  debug ("==> krb5_cache_acquire: get credentials from keytab");
	  krb5_cache_setup_creds (config);
	  if ((code = krb5_get_init_creds_keytab (context,
						  creds,
						  principal,
						  keytab,
						  0,
						  NULL,
						  &options))
	      && (code != EEXIST))
	    {
	      /* Failed to initialise credentials from keytab */
	      syslog (LOG_ERR,
		      "nss_ldap: %s(%d) while initialising credentials from keytab",
		      error_message (code), (int) code);
	      debug
		("==> krb5_cache_acquire get credentials from keytab failed %s(%d)",
		 error_message (code), (int) code);
	      debug
		("==> krb5_cache_acquire try refreshing from credential cache");
	      if ((code = krb5_cache_refresh (config)))
		{
		  debug
		    ("==> krb5_cache_acquire: cache credentials not usable");
		  free ((void *) creds);
		  creds = NULL;
		}
	      else if (cache_state == KRB5_CACHE_ACQUIRE)
		code = 1;
	    }
	  else
	    {
	      /* We have a set of credentials we now need to save them */
	      if ((code = krb5_cc_resolve (context, ccname, &cc)))
		{
		  syslog (LOG_ERR,
			  "nss_ldap: %s(%d) while resolving credential cache",
			  error_message (code), (int) code);
		  debug
		    ("==>krb5_cache_acquire: %s(%d) while resolving credential cache",
		     error_message (code), (int) code);
		}
	      else if ((code = krb5_cc_initialize (context, cc, principal))
		       && (code != EEXIST))
		{
		  /* Failed to initialize the cache try to use a default one instead */
		  syslog (LOG_ERR,
			  "nss_ldap: %s(%d) while initializing credential cache",
			  error_message (code), (int) code);
		  debug
		    ("==> krb5_cache_acquire: initializing credential cache failed %s(%d)",
		     error_message (code), (int) code);
		}
	      else
		{
		  debug
		    ("==> krb5_cache_acquire store credentials in cache file");
		  if ((code = krb5_cc_store_cred (context, cc, creds)))
		    {
		      syslog (LOG_ERR,
			      "nss_ldap: %s(%d) while storing credentials",
			      error_message (code), (int) code);
		      debug
			("==> krb5_cache_acquire: %s(%d) while storing credentials",
			 error_message (code), (int) code);
		    }
		  else
		    {
		      if (!creds->times.starttime)
			creds->times.starttime = creds->times.authtime;
		      debug ("==> krb5_cache_acquire: got new credentials");
		      cache_state = KRB5_CACHE_RUNNING;
		    }
		  if (cc != NULL)
		    {
		      if ((code = krb5_cc_close (context, cc)))
			{
			  debug
			    ("==> krb5_cache_acquire: cache %s close failed",
			     ccname ? ccname : "NULL");
			}
		    }
		}
	    }
	}
      if (keytab != NULL)
	{
	  krb5_kt_close (context, keytab);
	}
    }
  if (code)
    {
      debug ("<== krb5_cache_acquire: --> ERROR");
      cache_state = KRB5_CACHE_ERROR;
    }
  else
    {
      debug ("<== krb5_cache_acquire");
    }
  return (code);
}

int
do_init_krb5_cache (ldap_config_t * config)
{
  krb5_error_code code = 0;

  debug ("==> do_init_krb5_cache %s %s %s",
	 config->ldc_krb5_keytabname ? config->ldc_krb5_keytabname : "NULL",
	 config->ldc_krb5_ccname ? config->ldc_krb5_ccname : "NULL",
	 config->ldc_saslid ? config->ldc_saslid : "NULL");

  euid = geteuid ();

  /* Check to see if we are using sasl, if not then return as nothing to do */
  if (!(config->ldc_usesasl || (euid == 0 && config->ldc_rootusesasl)))
    {
      return (1);		/* Should we signal success? */
    }

  /* Check to see if we have swapped user since we were last called */
  if (__euid != euid)
    {				/* Could be first call but clear everything out anyway */
      krb5_cache_reset (config);
      __euid = euid;
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
      switch (cache_state)
	{

	case KRB5_CACHE_INIT:
	  code = krb5_cache_setup (config);
	  debug
	    ("==> do_init_krb5_cache ktname = %s, ccname = %s, saslid = %s, euid = %d",
	     ktname ? ktname : "NULL", ccname ? ccname : "NULL",
	     saslid ? saslid : "NULL", euid);
	  break;

	case KRB5_CACHE_RUNNING:
	  /*
	   * If we have credentials 
	   * and they are not expired or about to expire then OK!
	   */
	  if (credsOK (creds))
	    {
	      debug ("==> do_init_krb5_cache: return 0");
	      return (0);
	    }

	  if (credsEXPIRED (creds))
	    {
	      cache_state = KRB5_CACHE_EXPIRED;
	    }
	  else if (credsEXPIRING (creds))
	    {
	      cache_state = KRB5_CACHE_REFRESH;
	    }
	  else
	    {
	      /* Should not get here if things are OK so start again */
	      code = krb5_cache_reset (config);
	      cache_state = KRB5_CACHE_INIT;
	    }
	  break;

	case KRB5_CACHE_RENEW:
	  code = krb5_cache_renew (config);
	  break;

	case KRB5_CACHE_EXPIRED:
	  code = krb5_cache_acquire (config);
	  break;

	case KRB5_CACHE_REFRESH:
	  code = krb5_cache_refresh (config);
	  break;

	case KRB5_CACHE_ACQUIRE:
	  code = krb5_cache_acquire (config);
	  break;

	case KRB5_CACHE_ERROR:
	  /*
	   * Can't do anything while in ERROR state.
	   * ?? Wait for a few seconds to have passed and try again ??
	   * Otherwise how do we break out of this loop
	   * - reset will make same sequence happen if this is a hard problem
	   */
	  code = krb5_cache_reset (config);
	  break;

	default:
	  break;
	}
      if (code)
	{
	  debug ("==> do_init_krb5_cache: return %d", (int) code);
	  return (code);
	}
    }
  while (1);

   /*NOTREACHED*/
    debug ("==> do_init_krb5_cache: reinit ticket loop exit failure");
  return (1);
}

static char *saveccname = NULL;
/* This is shared into the environment so be careful */
#ifdef CONFIGURE_KRB5_CCNAME_ENV
static char envbuf[256];
#endif

int
do_select_krb5_cache (ldap_config_t * config)
{
  int result = 0;
  if (cache_state != KRB5_CACHE_RUNNING)
    {
      result = do_init_krb5_cache (config);
    }
  if (ccname != NULL)
    {
#ifdef CONFIGURE_KRB5_CCNAME_ENV
      char tmpbuf[256];
      char *oldccname = getenv ("KRB5CCNAME");
      if (saveccname != NULL)
	{
	  free ((void *) saveccname);
	  saveccname = NULL;
	}
      if (oldccname != NULL)
	{
	  strncpy (tmpbuf, oldccname, sizeof (tmpbuf));
	  tmpbuf[sizeof (tmpbuf) - 1] = '\0';
	  saveccname = (char *) malloc (strlen (tmpbuf) + 1);
	  strcpy (saveccname, tmpbuf);
	}
      snprintf (envbuf, sizeof (envbuf), "KRBCCNAME=%s", ccname);
      putenv (envbuf);
#elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
      OM_uint32 retval = 0;
      if (gss_krb5_ccache_name (&retval,
				(const char *) ccname,
				(const char **) &saveccname) !=
	  GSS_S_COMPLETE)
	{
	  debug
	    ("==> do_select_krb5_cache: unable to set default credential cache");
	  result = -1;
	}
#endif
    }
  return result;
}

int
do_restore_krb5_cache (ldap_config_t * config)
{
  int result = 0;
  if (saveccname != NULL)
    {
#ifdef CONFIGURE_KRB5_CCNAME_ENV
      snprintf (envbuf, sizeof (envbuf), "KRB5CCNAME=%s", saveccname);
      putenv (envbuf);
      free ((void *) saveccname);
#elif defined(CONFIGURE_KRB5_CCNAME_GSSAPI)
      OM_uint32 retval = 0;
      if (gss_krb5_ccache_name (&retval, (const char *) saveccname, NULL) !=
	  GSS_S_COMPLETE)
	{
	  debug
	    ("==> do_restore_krb5_cache: unable to restore default credential cache");
	  result = -1;
	}
#endif
      saveccname = NULL;
    }
  return result;
}
#endif /* CONFIGURE_KRB5_KEYTAB */
