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
 * 24th February 2010 - Integrated and cleaned up
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

typedef struct nss_ldap_krb5_state {
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
} nss_ldap_krb5_state_t;

#define credsOK(__ks__)				\
  (((__ks__)->creds != NULL) && (((__ks__)->creds->times.endtime - time(NULL)) > (2 * (__ks__)->skew)))

#define credsEXPIRING(__ks__)			\
  (((__ks__)->creds != NULL)			\
   && ((((__ks__)->creds->times.endtime - time(NULL)) <= (2 * (__ks__)->skew)) \
       && (((__ks__)->creds->times.endtime - time(NULL)) > (__ks__)->skew)))

#define credsEXPIRED(__ks__)			\
  (((__ks__)->creds == NULL)			\
   || ((((__ks__)->creds->times.renew_till - time(NULL)) <= (2 * (__ks__)->skew)) \
       || (((__ks__)->creds->times.endtime - time(NULL)) <= (__ks__)->skew)))

static void *do_krb5_cache_init(ldap_session_t *session);
static int do_krb5_cache_select (ldap_session_t *session);
static int do_krb5_cache_restore (ldap_session_t *session);
static void do_krb5_cache_close(ldap_session_t *session);

static void
do_krb5_cache_reset (nss_ldap_krb5_state_t *state)
{
  debug ("==> do_krb5_cache_reset");

  assert(state != NULL);

  if (state->context != NULL)
    {
      if (state->creds != NULL)
	{
	  krb5_free_creds (state->context, state->creds);
	  state->creds = NULL;
	}
#ifdef HEIMDAL
      if (state->creds2 != NULL)
	{
	  krb5_free_creds (state->context, state->creds2);
	  state->creds2 = NULL;
	}
#endif
      if (state->principal != NULL)
	{
	  krb5_free_principal (state->context, state->principal);
	  state->principal = NULL;
	}
      if (state->cc != NULL)
	{
	  krb5_cc_close (state->context, state->cc);
	  state->cc = NULL;
	}

      krb5_free_context (state->context);
      state->context = NULL;
    }

  state->skew = 0;
  state->autorenew = 0;

  if (state->ccname != NULL)
    {
      free (state->ccname);
      state->ccname = NULL;
    }
  if (state->ktname != NULL)
    {
      free (state->ktname);
      state->ktname = NULL;
    }
  if (state->saslid != NULL)
    {
      free (state->saslid);
      state->saslid = NULL;
    }

  state->cache_state = KRB5_CACHE_INIT;

  debug ("<== do_krb5_cache_reset");

  return;
}

static char *
do_krb5_cache_get_ktname (nss_ldap_krb5_state_t *state,
			  ldap_config_t * config,
			  int envOK)
{
  char *ktname = NULL;
  char buf[KT_PATH_MAX];

  assert(state != NULL && config != NULL);

  debug ("==> do_krb5_cache_get_ktname rootusekeytab=%d, rootusesasl=%d, rootkeytabname=%s",
	 config->ldc_krb5_rootusekeytab, config->ldc_rootusesasl, config->ldc_krb5_rootkeytabname);
  debug ("==> do_krb5_cache_get_ktname usekeytab=%d, usesasl=%d, keytabname=%s",
	 config->ldc_krb5_usekeytab, config->ldc_usesasl, config->ldc_krb5_keytabname);

  if (state->euid == 0 &&
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

  if (ktname == NULL && envOK)
    {
      /* Not setuid, so safe to read environment variables or use defaults */
      ktname = getenv ("KRB5_KTNAME");
      if (ktname == NULL)
	{
	  ktname = getenv ("NSS_LDAP_KRB5_KTNAME");
	}

      assert(state->context != NULL);

      if (krb5_kt_default_name (state->context, buf, KT_PATH_MAX) == 0)
	{
	  ktname = buf;
	}
    }

  debug ("<== do_krb5_cache_get_ktname: returns %s",
	 ktname ? ktname : "NULL");

  return ktname != NULL ? strdup(ktname) : NULL;
}

static char *
do_krb5_cache_get_ccname (nss_ldap_krb5_state_t *state,
				  ldap_config_t * config,
				  int envOK)
{
  char *ccname = NULL;

  debug ("==> do_krb5_cache_get_ccname");

  assert(state != NULL && config != NULL && state->context != NULL);

  if (state->euid == 0 && config->ldc_rootusesasl)
    {
      ccname = config->ldc_krb5_rootccname;
    }

  if (ccname == NULL && config->ldc_usesasl)
    {
      ccname = config->ldc_krb5_ccname;
    }

  if (ccname == NULL && envOK)
    {
      /* Not setuid, so safe to read environment variables */
      ccname = getenv ("KRB5CCNAME");
      if (ccname == NULL)
	{
	  ccname = getenv ("NSS_LDAP_KRB5CCNAME");
	}

      if (ccname == NULL)
	{
	  ccname = (char *)krb5_cc_default_name (state->context);
	}
    }

  debug ("<== do_krb5_cache_get_ccname: returns ccname=%s",
	 ccname ? ccname : "NULL");

  return (ccname != NULL) ? strdup (ccname) : NULL;
}

static char *
do_krb5_cache_get_saslid (nss_ldap_krb5_state_t *state, ldap_config_t * config)
{
  char *saslid = NULL;
  char defaultSaslId[sizeof("host/") + MAXHOSTNAMELEN] = "host/";

  debug ("==> do_krb5_cache_get_saslid");

  assert (state != NULL && config != NULL);

  if (state->euid == 0 && config->ldc_rootusesasl)
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

      debug (":== do_krb5_cache_get_saslid: get default principal name");

      p = &defaultSaslId[sizeof("host/") - 1];

      if (gethostname (p, MAXHOSTNAMELEN) != 0)
	{
	  debug ("<== _nss_ldap_krb5_cache_get_saslid: gethostname() failed - %s",
		 strerror (errno));
	  return NULL;
	}

      hostnamelen = strlen (p);

      if (strchr (p, '.') == NULL)
	{
	  if (getdomainname (p + 1, MAXHOSTNAMELEN - hostnamelen - 1) != 0)
	    {
	      debug ("<== _nss_ldap_krb5_cache_get_saslid: getdomainname() failed - %s",
		     strerror (errno));
	      return NULL;
	    }

	  *p = '.';
	}

      saslid = defaultSaslId;
    }

  debug ("<== do_krb5_cache_get_saslid: returns %s", saslid);

  return (saslid != NULL) ? strdup(saslid) : NULL;
}

static krb5_principal
do_krb5_cache_get_principal (nss_ldap_krb5_state_t *state)
{
  krb5_error_code code;
  krb5_principal principal;

  debug ("==> do_krb5_cache_get_principal");

  assert (state->context != NULL && state->saslid != NULL);

  code = krb5_parse_name (state->context, state->saslid, &principal);
  if (code != 0)
    {
      debug ("<== do_krb5_cache_get_principal: %s(%d) while parsing principal name %s",
	     error_message (code), (int) code, state->saslid);
      return NULL;
    }

  debug ("<== do_krb5_cache_get_principal: returns %p", principal);

  return principal;
}

/* Set up to manage the credentials cache */
static krb5_error_code
do_krb5_cache_setup (nss_ldap_krb5_state_t *state, ldap_config_t * config)
{
  krb5_error_code code;
  int envOK;
#ifndef HEIMDAL
  profile_t profile;
#endif

  debug ("==> do_krb5_cache_setup");

  assert(state != NULL);
  assert(config != NULL);

  if (state->context == NULL)
    {
      code = krb5_init_context (&state->context);
      if (code != 0)
	{
	  debug ("<== do_krb5_cache_setup: %s(%d) while initialising Kerberos library",
		 error_message (code), (int) code);
	  return code;
	}
    }
#ifndef HEIMDAL
  code = krb5_get_profile (state->context, &profile);
  if (code != 0)
    {
      debug ("<== do_krb5_cache_setup: %s(%d) while getting profile",
	     error_message (code), (int) code);
      return code;
    }

  code = profile_get_integer (profile,
			      "libdefaults",
			      "clockskew", 0, 5 * 60, &state->skew);
  if (code != 0)
    {
      debug ("<== do_krb5_cache_setup: %s(%d) while getting clockskew",
	     error_message (code), (int) code);
      return code;
    }

  profile_release (profile);
#else
  state->skew = state->context->max_skew;
#endif
  state->autorenew = (config->ldc_krb5_autorenew
				 || (state->euid == 0 && config->ldc_krb5_rootautorenew));

  /* It's safe to consult the environment if we're not setuid. */
  envOK = (getuid() == geteuid()) && (getgid() == getegid());

  state->ktname = do_krb5_cache_get_ktname (state, config, envOK);

  debug (":== do_krb5_cache_setup: keytab name %s",
	 state->ktname ? state->ktname : "NULL");

  state->ccname = do_krb5_cache_get_ccname (state, config, envOK);

  debug (":== do_krb5_cache_setup: credential cache name %s",
	 state->ccname ? state->ccname : "NULL");
  state->cache_state = KRB5_CACHE_REFRESH;

  debug ("<== do_krb5_cache_setup");

  return 0;
}

static int
do_krb5_cache_setup_creds (nss_ldap_krb5_state_t *state)
{
  debug ("==> do_krb5_cache_setup_creds");

  assert(state != NULL);

  if (state->creds == NULL)
    {
      state->creds = malloc (sizeof (*(state->creds)));
      if (state->creds == NULL)
	{
	  return ENOMEM;
	}
    }

  memset (state->creds, 0, sizeof (*(state->creds)));

  debug ("<== do_krb5_cache_setup_creds");

  return 0;
}

/* (Re)load the credentials cache into our local data */
static int
do_krb5_cache_refresh (nss_ldap_krb5_state_t *state)
{
  krb5_error_code code;
  char *principal_name = NULL;
  krb5_cc_cursor cursor;

  debug ("==> do_krb5_cache_refresh");

  assert(state != NULL);
  assert(state->ccname != NULL);
  assert(state->cc == NULL);

  debug (":== do_krb5_cache_refresh %s", state->ccname);

  code = krb5_cc_resolve (state->context,
			  state->ccname,
			  &state->cc);
  if (code != 0)
    {
      debug (":== do_krb5_cache_refresh: cache %s cannot be resolved: %s",
	     state->ccname ? state->ccname : "NULL", error_message(code));
      goto cleanup;
    }

  code = krb5_cc_get_principal (state->context,
				state->cc,
				&state->principal);
  if (code != 0)
    {
      debug (":== do_krb5_cache_refresh: cannot get principal from cache %s: %s",
	     state->ccname ? state->ccname : "NULL", error_message(code));
      goto cleanup;
    }

  /* Use the principal name from the cache rather than preconfigured saslid */
  code = krb5_unparse_name (state->context,
			    state->principal,
			    &principal_name);
  if (code != 0)
    {
      debug (":== do_krb5_cache_refresh: cannot unparse principal from cache %s: %s",
	     state->ccname ? state->ccname : "NULL", error_message(code));
      goto cleanup;
    }

  code = krb5_cc_start_seq_get (state->context, state->cc, &cursor);
  if (code != 0)
    {
      debug (":== do_krb5_cache_refresh: cache %s credentials not usable: %s",
	     state->ccname ? state->ccname : "NULL", error_message(code));
      goto cleanup;
    }

  code = do_krb5_cache_setup_creds (state);
  if (code != 0)
      goto cleanup;

  while (state->cache_state == KRB5_CACHE_REFRESH)
    {
      code = krb5_cc_next_cred (state->context,
				state->cc,
				&cursor,
				state->creds);
      if (code != 0)
	break;
    
      debug (":== do_krb5_cache_refresh: retrieved creds");

      if (credsOK (state))
	{
	  debug (":== do_krb5_cache_refresh: creds are OK --> RUNNING");
	  /* Reloaded cache is fine */
	  state->cache_state = KRB5_CACHE_RUNNING;
	  break;
	}

      if (credsEXPIRING (state))
	{
	  debug (":== do_krb5_cache_refresh: creds are EXPIRING");
	  /* Reloaded cache will expire shortly */
	  if (state->autorenew)
	    {
	      debug (":== do_krb5_cache_refresh: --> RENEW");
	      state->cache_state = KRB5_CACHE_RENEW;
	    }
	  else
	    {
	      debug (":== do_krb5_cache_refresh: --> EXPIRED");
	      state->cache_state = KRB5_CACHE_EXPIRED;
	    }
	  krb5_free_cred_contents (state->context, state->creds);
	  state->creds = NULL;
	}
      else if (credsEXPIRED (state))
	{
	  debug (":== do_krb5_cache_refresh: creds have EXPIRED --> EXPIRED");
	  /* Reload cache has expired */
	  state->cache_state = KRB5_CACHE_EXPIRED;
	  krb5_free_cred_contents (state->context, state->creds);
	  state->creds = NULL;
	}
    }

  code = krb5_cc_end_seq_get (state->context, state->cc, &cursor);
  if (code != 0)
    {
      debug (":== do_krb5_cache_refresh: cache %s scan failed to end cleanly",
	     state->ccname ? state->ccname : "NULL");
      goto cleanup;
    }

cleanup:
  if (principal_name != NULL)
      krb5_free_unparsed_name (state->context, principal_name);

  if (state->principal != NULL)
    {
      krb5_free_principal (state->context, state->principal);
      state->principal = NULL;
    }

  if (state->cc != NULL)
    {
      code = krb5_cc_close (state->context, state->cc);
      if (code != 0)
	{
	  debug (":== do_krb5_cache_refresh: cache %s close failed (ignoring): %s",
		 state->ccname ? state->ccname : "NULL",
		 error_message(code));
	}
      state->cc = NULL;
    }

  if (state->cache_state == KRB5_CACHE_REFRESH)
    {
      debug (":== do_krb5_cache_refresh: REFRESH --> ACQUIRE");
      state->cache_state = KRB5_CACHE_ACQUIRE; /* Try for a keytab */
    }

  debug ("<== do_krb5_cache_refresh");

  return code;
}

/* Renew an expired credentials cache */
static int
do_krb5_cache_renew (nss_ldap_krb5_state_t *state)
{
  krb5_error_code code = 0;
#ifdef HEIMDAL
  krb5_kdc_flags flags;
  krb5_realm *client_realm;
#endif

  debug ("==> do_krb5_cache_renew");

  assert(state != NULL);

  assert(state->autorenew == 0);
  if (!state->autorenew)
    {
      /* Should not be reached */
      debug ("<== do_krb5_cache_renew: renew called with autorenew off --> ERROR");
      state->cache_state = KRB5_CACHE_ERROR;
      return EINVAL;
    }

  /* Refresh or acquire will have set this up */
  assert (state->context != NULL && state->creds != NULL);

  /* renew ticket */
#ifndef HEIMDAL
  /* Overwrites contents of creds no storage allocation happening */
  assert(state->principal != NULL && state->cc != NULL);

  code = krb5_get_renewed_creds (state->context,
				 state->creds,
				 state->principal,
				 state->cc,
				 NULL);
#else
  flags.i = 0;
  flags.b.renewable = flags.b.renew = 1;

  if (state->creds2 == NULL)
    {
      state->creds2 = (krb5_creds *)calloc(1, sizeof(krb5_creds));
      if (state->creds2 == NULL)
	{
	  debug ("<== do_krb5_cache_renew: out of memory failed to allocate creds2");
	  return ENOMEM;
	}
    }
  assert(state->cc != NULL);

  code = krb5_cc_get_principal (state->context,
				state->cc,
				&state->creds2.client);
  if (code != 0)
    {
      debug ("<== do_krb5_cache_renew: %s(%d) while getting principal from credentials cache",
	 error_message (code), (int) code);
      state->cache_state = KRB5_CACHE_REFRESH;
      return code;
    }

  client_realm = krb5_princ_realm (state->context, state->creds2.client);

  code = krb5_make_principal (state->context,
			      &state->creds2.server,
			      *client_realm,
			      KRB5_TGS_NAME,
			      *client_realm,
			      NULL);
  if (code != 0)
    {
      debug ("<== krb5_cache_renew: %s(%d) while getting krbtgt principal",
	     error_message (code), (int) code);
      state->cache_state = KRB5_CACHE_REFRESH;
      return code;
    }

  /* I think there is a potential storage leak here as creds is written to */
  /* Need to check Heimdal code to see if it will overwrite or replace memory */

  code = krb5_get_kdc_cred (state->context,
			    state->cc, flags, NULL,
			    NULL, state->creds2,
			    &state->creds);
#endif
  if (code != 0)
    {
      debug (":== do_krb5_cache_renew: failed to renew credentials: %s(%d)",
	     error_message (code), (int) code);
      if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
	{
	  /* this can happen because of clock skew */
	  debug ("<== do_krb5_cache_renew: ticket has expired because of clock skew --> EXPIRED");
	  state->cache_state = KRB5_CACHE_EXPIRED;
	  code = 0;
	}
      else
	{
	  debug ("==> do_krb5_cache_renew: %s(%d) while renewing credentials",
		 error_message (code), (int) code);
	  state->cache_state = KRB5_CACHE_REFRESH;
	}
    }
  else
    {
      debug ("<== do_krb5_cache_renew: renewed creds --> RUNNING");
      state->cache_state = KRB5_CACHE_RUNNING;
    }


  return code;
}

/* Initialise the credentials cache from a keytab */
static int
do_krb5_cache_acquire (nss_ldap_krb5_state_t *state, ldap_config_t *config)
{
  krb5_error_code code;
  krb5_keytab keytab = NULL;
  krb5_get_init_creds_opt options;
  krb5_deltat rlife;
  int usekeytab;

  debug ("==> do_krb5_cache_acquire");

  /* No credentials; use keytab if configured */

  assert (state != NULL);
  assert (config != NULL);
  assert (state->context != NULL);

  /* use keytab to fill cache */

  usekeytab = config->ldc_krb5_usekeytab ||
      (state->euid == 0 && config->ldc_krb5_rootusekeytab);
  if (!usekeytab || state->ktname == NULL)
    {
      debug (":== do_krb5_cache_acquire: no usable keytab");
      code = ENOENT;
      goto finish_acquire_creds;
    }

  code = krb5_kt_resolve (state->context, state->ktname, &keytab);
  if (code != 0)
    {
      debug (":== do_krb5_cache_acquire: %s(%d) while resolving keytab filename %s",
	     error_message (code), (int) code, state->ktname);
      goto finish_acquire_creds;
    }

  if (state->saslid == NULL)
    {
      state->saslid = do_krb5_cache_get_saslid (state, config);
    }

  debug (":== do_krb5_cache_acquire: saslid=%s",
	 state->saslid ? state->saslid : "NULL");

  if (state->saslid && state->principal == NULL)
    {
      state->principal = do_krb5_cache_get_principal (state);
      if (state->principal == NULL)
	{
	  debug ("<== do_krb5_cache_acquire: no valid principal --> ERROR");
	  code = ENOENT;
	  goto finish_acquire_creds;
	}
    }

  krb5_get_init_creds_opt_init (&options);

  code = krb5_string_to_deltat (MAX_RENEW_TIME, &rlife);
  if (code != 0 || rlife == 0)
    {
      debug (":== do_krb5_cache_acquire: %s(%d) while setting renew lifetime value to %s",
	     error_message (code), (int) code, MAX_RENEW_TIME);
      code = (code == 0) ? 1 : code;
      goto finish_acquire_creds;
    }

  krb5_get_init_creds_opt_set_renew_life (&options, rlife);

  debug (":== do_krb5_cache_acquire: get credentials from keytab");

  code = do_krb5_cache_setup_creds (state);
  if (code != 0)
    {
      debug ("<== do_krb5_cache_acquire: failed to set up credentials");
      goto finish_acquire_creds;
    }

  code = krb5_get_init_creds_keytab (state->context,
				     state->creds,
				     state->principal,
				     keytab,
				     0,
				     NULL,
				     &options);
  if (code != 0 && code != EEXIST)
    {
      /* Failed to initialise credentials from keytab */
      debug (":== do_krb5_cache_acquire get credentials from keytab failed %s(%d)",
	     error_message (code), (int) code);
      debug (":== do_krb5_cache_acquire try refreshing from credential cache");
      code = do_krb5_cache_refresh (state);
      if (code != 0)
	{
	  debug (":== do_krb5_cache_acquire: cache credentials not usable");
	  free (state->creds);
	  state->creds = NULL;
	}
      else if (state->cache_state == KRB5_CACHE_ACQUIRE)
	code = EEXIST;
      goto finish_acquire_creds;
    }

  /* We have a set of credentials we now need to save them */

  code = krb5_cc_resolve (state->context,
			  state->ccname,
			  &state->cc);
  if (code != 0)
    {
      debug (":== do_krb5_cache_acquire: %s(%d) while resolving credential cache",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }
  
  code = krb5_cc_initialize (state->context,
			     state->cc,
			     state->principal);
  if (code != 0 && code != EEXIST)
    {
      /* Failed to initialize the cache try to use a default one instead */
      debug (":== do_krb5_cache_acquire: initializing credential cache failed %s(%d)",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }

  code = krb5_cc_store_cred (state->context,
			     state->cc,
			     state->creds);
  if (code != 0)
    {
      debug (":== do_krb5_cache_acquire: %s(%d) while storing credentials",
	     error_message (code), (int) code);
      goto finish_acquire_creds;
    }

  if (state->creds->times.starttime == 0)
    {
      state->creds->times.starttime = state->creds->times.authtime;
    }

  debug (":== do_krb5_cache_acquire: got new credentials");
  state->cache_state = KRB5_CACHE_RUNNING;

finish_acquire_creds:
  if (state->cc != NULL)
    {
      code = krb5_cc_close (state->context, state->cc);
      if (code != 0)
	{
	  debug (":== do_krb5_cache_acquire: cache %s close failed",
		 state->ccname ? state->ccname : "NULL");
	}
      state->cc = NULL;
    }
 
  if (keytab != NULL)
    {
      code = krb5_kt_close (state->context, keytab);
    }

  if (code != 0)
    {
      debug ("<== do_krb5_cache_acquire: --> ERROR");
      state->cache_state = KRB5_CACHE_ERROR;
    }
  else
    {
      debug ("<== do_krb5_cache_acquire");
    }

  return code;
}

/*
 * Entry points into the kerberos support
 */
static void *
do_krb5_cache_init (ldap_session_t *session)
{
  krb5_error_code code;
  ldap_session_opaque_t state_p = NULL;
  nss_ldap_krb5_state_t *state = NULL;
  ldap_config_t * config = NULL;
  uid_t euid = geteuid();

  debug ("==> do_krb5_cache_init");

  if (session == NULL)
    {
      debug ("<== do_krb5_cache_init: called with NULL session ignoring krb5 initialisation");
      return NULL;
    }

  config = session->ls_config;
  if (config == NULL)
    {
      debug("<== do_krb5_cache_init: no configuration available ignoring krb5 initialisation");
      return NULL;
    }

  debug (":== do_krb5_cache_init: keytabname=%s, ccname=%s, saslid=%s, "
	"rootkeytabname=%s, rootccname=%s, rootsaslid=%s",
	 config->ldc_krb5_keytabname	  ? config->ldc_krb5_keytabname	      : "NULL",
	 config->ldc_krb5_ccname	  ? config->ldc_krb5_ccname	      : "NULL",
	 config->ldc_saslid		  ? config->ldc_saslid		      : "NULL",
	 config->ldc_krb5_rootkeytabname  ? config->ldc_krb5_rootkeytabname   : "NULL",
	 config->ldc_krb5_rootccname	  ? config->ldc_krb5_rootccname	      : "NULL",
	 config->ldc_rootsaslid		  ? config->ldc_rootsaslid	      : "NULL");

  /*
   * Check to see if we are using sasl, if not then return as nothing to do
   * This is a guard as we would not expect to be called unless sasl is running
   */
  if (!config->ldc_usesasl && (euid != 0 || !config->ldc_rootusesasl))
    {
      return NULL;
    }

  state_p = __nss_ldap_find_opaque(session, LSO_KRB5);
  if (state_p == NULL)
    {
      state_p = __nss_ldap_allocate_opaque(session, LSO_KRB5);
      if (state_p == NULL)
	{
	  debug ("<== do_krb5_cache_init - out of memory while allocating state object container");
	  return NULL;
	}
    }

  state = state_p->lso_data;
  if (state == NULL)
    {
      state = state_p->lso_data = (nss_ldap_krb5_state_t *)calloc(1, sizeof(nss_ldap_krb5_state_t));
      if (state == NULL)
	{
	  __nss_ldap_free_opaque(session, LSO_KRB5);
	  debug ("<== do_krb5_cache_init - out of memory while allocating state object");
	  return NULL;
	}
      state->euid = -1; /* force reset */
    }

  /* Check to see if we have swapped user since we were last called */
  if (state->euid != euid)
    {
      /* Could be first call but clear everything out anyway */
      do_krb5_cache_reset (state);
      state->euid = euid;
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
      switch (state->cache_state)
	{

	case KRB5_CACHE_INIT:
	  code = do_krb5_cache_setup (state, config);
	  debug (":== do_krb5_cache_init: ktname=%s, ccname=%s, saslid=%s, euid=%d",
		 state->ktname ? state->ktname : "NULL",
		 state->ccname ? state->ccname : "NULL",
		 state->saslid ? state->saslid : "NULL",
		 state->euid);
	  break;

	case KRB5_CACHE_RUNNING:
	  /*
	   * If we have credentials 
	   * and they are not expired or about to expire then OK!
	   */
	  if (credsOK (state))
	    {
	      debug ("<== do_krb5_cache_init: return OK");
	      return state;
	    }

	  if (credsEXPIRED (state))
	    {
	      state->cache_state = KRB5_CACHE_EXPIRED;
	    }
	  else if (credsEXPIRING (state))
	    {
	      state->cache_state = KRB5_CACHE_REFRESH;
	    }
	  else
	    {
	      /* Should not get here if things are OK so start again */
	      debug(":== do_krb5_cache_init: RESET credentials as we got into an unusual state");
	      do_krb5_cache_reset (state);
	      state->cache_state = KRB5_CACHE_INIT;
	    }
	  break;

	case KRB5_CACHE_RENEW:
	  debug(":== do_krb5_cache_init: RENEW credentials");
	  code = do_krb5_cache_renew (state);
	  break;

	case KRB5_CACHE_EXPIRED:
	  debug(":== do_krb5_cache_init: ACQUIRE credentials they EXPIRED");
	  code = do_krb5_cache_acquire (state, config);
	  break;

	case KRB5_CACHE_REFRESH:
	  debug(":== do_krb5_cache_init: REFRESH credentials");
	  code = do_krb5_cache_refresh (state);
	  break;

	case KRB5_CACHE_ACQUIRE:
	  debug(":== do_krb5_cache_init: ACQUIRE credentials  first time");
	  code = do_krb5_cache_acquire (state, config);
	  break;

	case KRB5_CACHE_ERROR:
	  /*
	   * Can't do anything while in ERROR state.
	   * So release all of the structures and return failure,
	   * let the higher level code try again later.
	   */
	  do_krb5_cache_close(session);
	  debug(":== do_krb5_cache_init: reset cache for ERROR state");
	  code = -1;
	  break;

	default:
	  debug(":== do_krb5_cache_init: got a default entry for state %d this is an error",
		state->cache_state);
	  break;
	}
      if (code != 0)
	{
	  debug ("<== krb5_cache_init: got %d", (int) code);
	  return state;
	}
    }
  while (1);

  /*NOTREACHED*/
  debug ("<== krb5_cache_init: reinit ticket loop exit failure");

  return state;
}

static int
do_krb5_cache_select (ldap_session_t *session)
{
  int result = 0;
  ldap_session_opaque_t state_p = NULL;
  nss_ldap_krb5_state_t *state = NULL;

  debug("==> do_krb5_cache_select");

  if (session == NULL)
    {
      debug ("<== do_krb5_cache_select: called with NULL session cache not running");
      return -1;
    }

  state_p = __nss_ldap_find_opaque(session, LSO_KRB5);
  if (state_p == NULL)
      state = (nss_ldap_krb5_state_t *)do_krb5_cache_init (session);
  else 
      state = (nss_ldap_krb5_state_t *)state_p->lso_data;

  if (state == NULL)
    {
      debug ("<== do_krb5_cache_select - cache initialisation failed no state object allocated");
      return -1;
    }

  if (state->cache_state != KRB5_CACHE_RUNNING)
    {
      debug ("<== do_krb5_cache_select - cache initialisation failed - cache not running");
      return -1;
    }

  if (state->ccname != NULL)
    {
      OM_uint32 minor;
      krb5_error_code code;

      code = gss_krb5_ccache_name (&minor,
				   (const char *) state->ccname,
				   (const char **) &state->saveccname);
      if (code != GSS_S_COMPLETE)
	{
	  debug (":== do_krb5_cache_select: unable to set default credential cache - retval %d", retval);
	  result = -1;
	}
      debug(":== do_krb5_cache_select: ccname=%s", state->ccname);
    }
  else
    {
      debug(":== do_krb5_cache_select: ccname is NULL");
    }

  debug ("<== do_krb5_cache_select returns result=%d", result);

  return result;
}

static int
do_krb5_cache_restore (ldap_session_t *session)
{
  int result = 0;
  ldap_session_opaque_t state_p;
  nss_ldap_krb5_state_t *state;
  OM_uint32 retval;
  krb5_error_code code;

  debug("==> do_krb5_cache_restore");

  if (session == NULL)
    {
      debug ("<== do_krb5_cache_restore: called with NULL session cache not running");
      return -1;
    }

  state_p = __nss_ldap_find_opaque(session, LSO_KRB5);
  if (state_p == NULL)
    {
      debug ("<== do_krb5_cache_restore - cache not initialised no state object container allocated");
      return -1;
    }
  state = (nss_ldap_krb5_state_t *)state_p->lso_data;
  if (state == NULL)
    {
      __nss_ldap_free_opaque(session, LSO_KRB5);
      debug ("<== do_krb5_cache_restore - cache not initialised no state object allocated");
      return -1;
    }

  if (state->cache_state != KRB5_CACHE_RUNNING)
    {
      debug ("<== do_krb5_cache_restore - cache not initialised - cache not running");
      return -1;
    }

  code = gss_krb5_ccache_name (&retval, (const char *) state->saveccname, NULL);
  if (code != GSS_S_COMPLETE)
    {
      debug (":== do_krb5_cache_restore: unable to restore default credential cache- retval %d", retval);
      result = -1;
    }

  state->saveccname = NULL;

  debug ("<== do_krb5_cache_restore: returns result=%d", result);

  return result;
}

static void
do_krb5_cache_close (ldap_session_t *session)
{
  ldap_session_opaque_t state_p = NULL;
  nss_ldap_krb5_state_t *state = NULL;

  debug ("==> do_krb5_cache_close");

  if (session == NULL)
    {
      debug ("<== do_krb5_cache_close: called with NULL session cache not running");
      return;
    }

  state_p = __nss_ldap_find_opaque(session, LSO_KRB5);

  if (state_p != NULL
      && (state = (nss_ldap_krb5_state_t *)(state_p->lso_data)) != NULL)
    {
      do_krb5_cache_reset(state);
    }

  __nss_ldap_free_opaque(session, LSO_KRB5);

  debug ("<== do_krb5_cache_close");

  return;
}

#endif  /*  defined(CONFIGURE_KRB5_KEYTAB) */

#if defined(CONFIGURE_KRB5_CCNAME)

static const char *saveccname = NULL;
# if defined(CONFIGURE_KRB5_CCNAME_ENV)
static char envbuf[256];
#endif

static void
do_krb5_cache_init (ldap_session_t * session)
{
  return;
}

static int
do_krb5_cache_select (ldap_session_t * session)
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
do_krb5_cache_restore (ldap_session_t *session)
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
do_krb5_cache_close (ldap_session_t *session)
{
  return;
}

#endif /*  defined(CONFIGURE_KRB5_CCNAME) */

#if !defined(CONFIGURE_KRB5_KEYTAB) && !defined(CONFIGURE_KRB5_CCNAME)
static void *
do_krb5_cache_init (ldap_session_t *session)
{
  return NULL;
}

static int
do_krb5_cache_select (ldap_session_t *session)
{
  return 0;
}

static int
do_krb5_cache_restore (ldap_session_t *session)
{
  return 0;
}

static void
do_krb5_cache_close (ldap_session_t *session)
{
  return;
}

#endif /* !defined(CONFIGURE_KRB5_KEYTAB) && !defined(CONFIGURE_KRB5_CCNAME) */

ldap_session_mech_t
do_krb5_cache(void)
{
  ldap_session_mech_t krb5_cache_mech = NULL;

  debug("==> do_krb5_cache");

  krb5_cache_mech = __nss_ldap_mech_setup(LSM_KRB5,
					  do_krb5_cache_init,
					  do_krb5_cache_select,
					  do_krb5_cache_restore,
					  do_krb5_cache_close);

  if (krb5_cache_mech == NULL)
    {
      debug (":== do_krb5_cache: Failed to allocate mech structure for kerberos mechs");
    }

  debug ("<== do_krb5_cache: return %p", krb5_cache_mech);

  return krb5_cache_mech;
}

