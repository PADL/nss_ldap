/* Copyright (C) 1997-2010 Luke Howard.
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

/*
 * Support DNS SRV records. I look up the SRV record for
 * _ldap._tcp.gnu.org.
 * and build the DN DC=gnu,DC=org.
 * Thanks to Assar & co for resolve.[ch].
 */

static char rcsId[] =
  "$Id$";

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>

#include <assert.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "util.h"
#include "resolve.h"
#include "dnsconfig.h"


/* map gnu.org into DC=gnu,DC=org */
NSS_STATUS
_nss_ldap_getdnsdn (char *src_domain,
		    char **rval, char **buffer, size_t * buflen)
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

static int
priority_sort(const void *r1, const void *r2)
{
  struct resource_record **rr1 = (struct resource_record **)r1;
  struct resource_record **rr2 = (struct resource_record **)r2;
  unsigned int total;

  if ((*rr1)->u.srv->priority == (*rr2)->u.srv->priority)
    {
      /* Weight-based selection */
      if ((*rr1)->u.srv->weight == 0 && (*rr2)->u.srv->weight == 0)
        {
          return (rand() % 2) ? -1 : 1;
        }

      total = (*rr1)->u.srv->weight + (*rr2)->u.srv->weight;
      return (rand() % total < (*rr1)->u.srv->weight) ? -1 : 1;
    }
  else if ((*rr1)->u.srv->priority < (*rr2)->u.srv->priority)
    {
      return -1;
    }

  /* rr1 > rr2 */
  return 1;
}

NSS_STATUS
_nss_ldap_mergeconfigfromdns (ldap_config_t * result,
			      char **buffer, size_t *buflen)
{
  NSS_STATUS stat = NSS_SUCCESS;
  struct dns_reply *r;
  struct resource_record *rr;
  char domain[MAXHOSTNAMELEN + 1];
  char *pDomain;
  char uribuf[NSS_BUFSIZ];
  int srv_count = 0;
  int i;
  struct resource_record **srr;

  debug ("==> _nss_ldap_mergeconfigfromdns");

  if ((_res.options & RES_INIT) == 0 && res_init () == -1)
    {
      return NSS_UNAVAIL;
    }

  if (result->ldc_srv_site != NULL)
    {
      snprintf (domain, sizeof (domain), "_ldap._tcp.%s._sites.%s.",
		result->ldc_srv_site,
		result->ldc_srv_domain ? result->ldc_srv_domain : _res.defdname);
    }
  else
    {
      snprintf (domain, sizeof (domain), "_ldap._tcp.%s.", 
		result->ldc_srv_domain ? result->ldc_srv_domain : _res.defdname);
    }
  pDomain = domain;

  r = dns_lookup (pDomain, "srv");
  if (r == NULL)
    {
      return NSS_NOTFOUND;
    }

  for (rr = r->head; rr != NULL; rr = rr->next)
    {
      if (rr->type == T_SRV)
	srv_count++;
    }

  debug (":== _nss_ldap_mergeconfigfromdns: retrieved %d SRV records", srv_count);

  srr = (struct resource_record **)calloc (srv_count, sizeof(struct resource_record *));
  if (srr == NULL)
    {
      dns_free_data (r);
      return NSS_NOTFOUND;
    }

  for (rr = r->head, i = 0; rr != NULL; rr = rr->next, i++)
    {
      if (rr->type == T_SRV)
	srr[i] = rr;
    }

  qsort(srr, srv_count, sizeof(struct resource_record *), priority_sort);

  for (i = 0; i < srv_count; i++)
    {
      rr = srr[i];
      snprintf (uribuf, sizeof(uribuf), "ldap%s://%s:%d",
		(rr->u.srv->port == LDAPS_PORT) ? "s" : "",
		rr->u.srv->target,
		rr->u.srv->port);

      stat = _nss_ldap_add_uri (result, uribuf, buffer, buflen);
      if (stat != NSS_SUCCESS)
	{
	  break;
	}
    }

  debug (":== _nss_ldap_mergeconfigfromdns: processed sort array");
  free(srr);

  dns_free_data (r);
  stat = NSS_SUCCESS;

  if (result->ldc_base == NULL)
    {
      stat = _nss_ldap_getdnsdn (_res.defdname, &result->ldc_base,
				 buffer, buflen);
    }

  debug ("<== _nss_ldap_mergeconfigfromdns");

  return stat;
}

