/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see LICENSE.OpenLDAP
 */

#include "config.h"

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && defined(HAVE_SASL_H)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sasl.h> 

#include <ldap.h>
#include "ldap-lutil.h"


typedef struct lutil_sasl_defaults_s
{
  char *mech;
  char *realm;
  char *authcid;
  char *passwd;
  char *authzid;
}
lutilSASLdefaults;


void *
_nss_ldap_sasl_defaults (LDAP * ld,
			 char *mech,
			 char *realm,
			 char *authcid, char *passwd, char *authzid)
{
  lutilSASLdefaults *defaults;

  defaults = ber_memalloc (sizeof (lutilSASLdefaults));

  if (defaults == NULL)
    return NULL;

  defaults->mech = mech;
  defaults->realm = realm;
  defaults->authcid = authcid;
  defaults->passwd = passwd;
  defaults->authzid = authzid;

  if (defaults->mech == NULL)
    {
      ldap_get_option (ld, LDAP_OPT_X_SASL_MECH, &defaults->mech);
    }
  if (defaults->realm == NULL)
    {
      ldap_get_option (ld, LDAP_OPT_X_SASL_REALM, &defaults->realm);
    }
  if (defaults->authcid == NULL)
    {
      ldap_get_option (ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid);
    }
  if (defaults->authzid == NULL)
    {
      ldap_get_option (ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid);
    }

  return defaults;
}

/* Simple function that returns the pre-loaded token.  No interaction is
   allowed when we're inside of an nss backend! */
static int
interaction (sasl_interact_t * interact, lutilSASLdefaults * defaults)
{
  const char *dflt = interact->defresult;

  int noecho = 0;
  int challenge = 0;

  switch (interact->id)
    {
    case SASL_CB_GETREALM:
      if (defaults)
	dflt = defaults->realm;
      break;
    case SASL_CB_AUTHNAME:
      if (defaults)
	dflt = defaults->authcid;
      break;
    case SASL_CB_PASS:
      if (defaults)
	dflt = defaults->passwd;
      noecho = 1;
      break;
    case SASL_CB_USER:
      if (defaults)
	dflt = defaults->authzid;
      break;
    case SASL_CB_NOECHOPROMPT:
      noecho = 1;
      challenge = 1;
      break;
    case SASL_CB_ECHOPROMPT:
      challenge = 1;
      break;
    }

  if (dflt && !*dflt)
    dflt = NULL;

  /* input must be empty */
  interact->result = strdup ((dflt && *dflt) ? dflt : "");
  interact->len = interact->result ? strlen (interact->result) : 0;

  if (defaults && defaults->passwd && interact->id == SASL_CB_PASS)
    {
      /* zap password after first use */
      memset (defaults->passwd, '\0', strlen (defaults->passwd));
      defaults->passwd = NULL;
    }

  return LDAP_SUCCESS;
}

int
_nss_ldap_sasl_interact (LDAP * ld, unsigned flags, void *defaults, void *in)
{
  sasl_interact_t *interact = in;

  if (flags == LDAP_SASL_INTERACTIVE)
    {
      fputs ("SASL Interaction\n", stderr);
    }

  while (interact->id != SASL_CB_LIST_END)
    {
      int rc = interaction (interact, defaults);

      if (rc)
	return rc;
      interact++;
    }

  return LDAP_SUCCESS;
}
#endif
