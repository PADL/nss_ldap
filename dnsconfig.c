
/* Copyright (C) 1997 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.
   (The author maintains a non-exclusive licence to distribute this file
   under their own conditions.)

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#ifdef NeXT
/* hack */
#include <bsd/resolv.h>
#else
#include <resolv.h>
#endif
#include <lber.h>
#include <ldap.h>

#include <string.h>

#ifdef GNU_NSS
#include <nss.h>
#elif defined(IRS_NSS)
#include "irs-nss.h"
#elif defined(SUN_NSS)
#include <thread.h>
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

/*
 * Support DNS SRV records. I look up the SRV record for
 * _ldap._tcp.gnu.org.
 * and build the DN DC=gnu,DC=org.
 * Thanks to Assar & co for resolve.[ch].
 */

#include "ldap-nss.h"
#include "globals.h"
#include "util.h"
#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif
#include "resolve.h"
#include "dnsconfig.h"

/* map gnu.org into DC=gnu,DC=org */
NSS_STATUS 
_nss_ldap_getdnsdn (
		     char *src_domain,
		     char **rval,
		     char **buffer,
		     size_t * buflen)
{
  char *p;
  int len = 0;
#ifdef HAVE_STRTOK_R
  char *st = NULL;
#endif
  char *bptr;
  char *domain, *domain_copy;

  /* we need to take a copy of domain, because strtok() modifies
   * it in place. Bad.
   */
  domain_copy = strdup (src_domain);
  if (domain_copy == NULL)
    {
      return NSS_TRYAGAIN;
    }

  domain = domain_copy;

  bptr = *rval = *buffer;
  **rval = '\0';

#ifndef HAVE_STRTOK_R
  while ((p = strtok (domain, ".")))
#else
  while ((p = strtok_r (domain, ".", &st)))
#endif
    {
      len = strlen (p);

      if (*buflen < (size_t) (len + DC_ATTR_AVA_LEN + 1 /* D C = [,|\0] */ ))
	{
	  free (domain_copy);
	  return NSS_TRYAGAIN;
	}

      if (domain == NULL)
	{
	  strcpy (bptr, ",");
	  bptr++;
	}
      else
	{
	  domain = NULL;
	}

      strcpy (bptr, DC_ATTR_AVA);
      bptr += DC_ATTR_AVA_LEN;

      strcpy (bptr, p);
      bptr += len;		/* don't include comma */
      *buffer += len + DC_ATTR_AVA_LEN + 1;
      *buflen -= len + DC_ATTR_AVA_LEN + 1;
    }

  if (bptr != NULL)
    {
      (*rval)[bptr - *rval] = '\0';
    }

  free (domain_copy);

  return NSS_SUCCESS;
}


NSS_STATUS 
_nss_ldap_readconfigfromdns (
			      ldap_config_t ** presult,
			      char *buf,
			      size_t buflen
)
{
  NSS_STATUS stat = NSS_SUCCESS;
  struct dns_reply *r;
  struct resource_record *rr;
  char domain[MAXHOSTNAMELEN + 1];
  char *bptr;
  ldap_config_t *result;

  bptr = buf;

  /* Bogus... this never gets freed... */
  if (*presult == NULL)
    {
      *presult = (ldap_config_t *) calloc (1, sizeof (*result));
      if (*presult == NULL)
	return NSS_UNAVAIL;
    }

  result = *presult;
  result->ldc_scope = LDAP_SCOPE_SUBTREE;
  result->ldc_host = NULL;
  result->ldc_base = NULL;
  result->ldc_port = LDAP_PORT;
  result->ldc_binddn = NULL;
  result->ldc_bindpw = NULL;
  result->ldc_next = result;

  __nss_dns_lock ();

  if ((_res.options & RES_INIT) == 0 && res_init () == -1)
    {
      __nss_dns_unlock ();
      return NSS_UNAVAIL;
    }

#ifdef RFC2052BIS
  snprintf (domain, sizeof (domain), "_ldap._tcp.%s.", _res.defdname);
#else
  snprintf (domain, sizeof (domain), "ldap.tcp.%s.", _res.defdname);
#endif /* RFC2307BIS */

  r = dns_lookup (domain, "srv");
  if (r == NULL)
    {
      __nss_dns_unlock ();
      return NSS_NOTFOUND;
    }

  /* XXX sort by priority */
  for (rr = r->head; rr != NULL; rr = rr->next)
    {
      if (rr->type == T_SRV)
	{
	  int len;

	  if (result->ldc_host != NULL)
	    {
	      /* need more space. Need to revise memory mgmnt in ldap-nss.c */

	      result->ldc_next = (ldap_config_t *) malloc (sizeof (*result));
	      if (result->ldc_next == NULL)
		{
		  return NSS_UNAVAIL;
		}
	      result = result->ldc_next;

	      result->ldc_scope = LDAP_SCOPE_SUBTREE;
	      result->ldc_binddn = NULL;
	      result->ldc_bindpw = NULL;
	      result->ldc_next = result;
	    }

	  /* Server Host */
	  strcpy (bptr, rr->u.srv->target);
	  result->ldc_host = bptr;

	  len = strlen (rr->u.srv->target);
	  bptr += len + 1;
	  buflen -= len + 1;

	  /* Port */
	  result->ldc_port = rr->u.srv->port;

	  /* DN */
	  stat = _nss_ldap_getdnsdn (_res.defdname,
				     &result->ldc_base,
				     &bptr,
				     &buflen);
	  if (stat != NSS_SUCCESS)
	    {
	      __nss_dns_unlock ();
	      return stat;
	    }
	}
    }

  __nss_dns_unlock ();
  stat = NSS_SUCCESS;

  return stat;
}
