/* Copyright (C) 1997 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@xedoc.com>, 1997.
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
	Utility functions. Some of this code was originally developed in ypldapd
	and LDAPAgent. Those portions are now "derived works" from this code,
	and those portions are subject to the licence above. This code has been
	heavily modified (and improved!) for nss_ldap.
 */

#include "ldap-nss.h"
#include "globals.h"
#include "util.h"

static char rcsId[] = "$Id$";

NSS_STATUS _nss_ldap_getdomainname(
	LDAP *ld,
	LDAPMessage *entry,
	char **rval,
	char **buffer,
	size_t *buflen)
{
	char **components;
	char **cptr;
	char *bptr = NULL;
	char *dn;
	NSS_STATUS stat = NSS_NOTFOUND;

	dn = ldap_get_dn(ld, entry);
	if (dn == NULL)
		{
		return NSS_NOTFOUND;
		}

	components = ldap_explode_dn(dn, 0);
	if (components == NULL)
		{
#ifdef NETSCAPE_SDK
		ldap_memfree(dn);
#endif
		return NSS_NOTFOUND;
		}

	for (cptr = components; *cptr != NULL; cptr++)
		{
		char *rdn = *cptr;
		char *p = rdn;
#ifdef HAVE_STRTOK_R
		char *st = NULL;
#endif

#ifndef HAVE_STRTOK_R
		for (p = strtok(rdn, "+");
#else
		for (p = strtok_r(rdn, "+", &st);
#endif
			p != NULL;
#ifndef HAVE_STRTOK_R
			p = strtok(NULL, "+"))
#else
			p = strtok_r(NULL, "+", &st))
#endif
			{
			if (strncasecmp(p, DC_ATTR_AVA, DC_ATTR_AVA_LEN) == 0)
				{
				register int len;

				/* advance pointer past dc= */
				p += DC_ATTR_AVA_LEN;
				len = strlen(p);

				if (*buflen < (size_t)(len + 1))
					{
#ifdef NETSCAPE_SDK
					ldap_memfree(dn);
#endif
					free(components);
					return NSS_TRYAGAIN;
					}

				if (bptr == NULL)
					{
					/* first time around, get some memory */
					bptr = *rval = *buffer;
					**rval = '\0';
					}
				else
					{
					/* otherwise, append domain separator (period) */
					strcpy(bptr, ".");
					bptr++;
					}

				/* copy domain component and advance pointers */
				strncpy(bptr, p, len);
				bptr += len;
				*buffer += len + 1;
				*buflen -= len + 1;
				break; /* only one dc= per RDN */
				}
			}
		}

	if (bptr != NULL)
		{
		/* *rval points to the start of the domainname, bptr to the end of it */
		(*rval)[bptr - *rval] = '\0';
		stat = NSS_SUCCESS;
		}

#ifdef NETSCAPE_SDK
	ldap_memfree(dn);
#endif
	free(components);

	return stat;
}


NSS_STATUS _nss_ldap_getrdnvalue(
	LDAP *ld,
	LDAPMessage *entry,
	char **rval,
	char **buffer,
	size_t *buflen)
{
	char **exploded_dn;
	char *dn;
	char *rdnvalue = NULL;

	int rdnlen = 0;

	dn = ldap_get_dn(ld, entry);
	if (dn == NULL)
		{
		return NSS_NOTFOUND;
		}

	exploded_dn = ldap_explode_dn(dn, 0);

	if (exploded_dn != NULL)
		{
		/* attempt to get the naming attribute's principal
		 * value by parsing the RDN. We need to support
		 * multivalued RDNs.
		 */
		char *p, *r = *exploded_dn;
#ifdef HAVE_STRTOK_R
		char *st = NULL;
#endif

#ifndef HAVE_STRTOK_R
		for (p = strtok(r, "+");
#else
		for (p = strtok_r(r, "+", &st);
#endif
			p != NULL;
#ifndef HAVE_STRTOK_R
			p = strtok(NULL, "+"))
#else
			p = strtok_r(NULL, "+", &st))
#endif
			{
			if (strncasecmp(p, CN_ATTR_AVA, CN_ATTR_AVA_LEN) == 0)
				{
				p += CN_ATTR_AVA_LEN;
				rdnlen = strlen(p);
				if (*buflen < rdnlen)
					{
#ifdef NETSCAPE_SDK
					ldap_memfree(dn);
#endif
					free(exploded_dn);
					return NSS_TRYAGAIN;
					}
				rdnvalue = *buffer;
				strncpy(rdnvalue, p, rdnlen);
				break;
				}
			if (r != NULL)
				r = NULL;
			}
		}

	if (rdnvalue == NULL)
		{
		char **vals;

		vals = ldap_get_values(ld, entry, CN_ATTR);

		if (vals != NULL)
			{
			rdnlen = strlen(*vals);
			if (*buflen >= rdnlen)
				{
				rdnvalue = *buffer;
				strncpy(rdnvalue, *vals, rdnlen);
				}
			ldap_value_free(vals);
			}
		}

#ifdef NETSCAPE_SDK
	ldap_memfree(dn);
#endif

	if (exploded_dn != NULL)
		{
		free(exploded_dn);
		}

	if (*rval != NULL && rdnvalue != NULL)
		{
		rdnvalue[rdnlen] = '\0';
		*buffer += rdnlen + 1;
		*buflen -= rdnlen + 1;
		*rval = rdnvalue;
		return NSS_SUCCESS;
		}
	
	return NSS_NOTFOUND;
}

NSS_STATUS _nss_ldap_readconfig(
        ldap_config_t *result,
        char *buf,
        size_t buflen
)
{
	FILE *fp;
	char b[NSS_LDAP_CONFIG_BUFSIZ], *p;
	NSS_STATUS stat = NSS_SUCCESS;

	p = buf;

	result->ldc_scope = LDAP_SCOPE_SUBTREE;
	result->ldc_host = NULL;
	result->ldc_base = NULL;
	result->ldc_port = LDAP_PORT;
	result->ldc_binddn = NULL;
	result->ldc_bindpw = NULL;
	result->ldc_next = result;

	fp = fopen(NSS_LDAP_PATH_CONF, "r");
	if (fp == NULL)
		{
		return NSS_UNAVAIL;
		}

	while(fgets(b, sizeof(b), fp) != NULL)
		{
#ifdef HAVE_STRTOK_R
		char *st = NULL;
#endif
		char *k, *v;
		int len;
		char **t = NULL;

		if (*b == '\0' || *b == '#')
			continue;

#ifdef HAVE_STRTOK_R
		k = strtok_r(b, " \t", &st);
#else
		k = strtok(b, " \t");
#endif
		if (k == NULL)
			continue;

#ifdef HAVE_STRTOK_R
		v = strtok_r(NULL, "", &st);
#else
		k = strtok(NULL, "");
#endif
		if (v == NULL || *v == '\0')
			continue;

		len = strlen(v);

		v[len - 1] = '\0';

		len--;

		if (buflen < (size_t)(len + 1))
			{
			stat = NSS_TRYAGAIN;
			break;
			}

		if (!strcmp(k, NSS_LDAP_KEY_HOST))
			{
			t = &result->ldc_host;
			}
		else if (!strcmp(k, NSS_LDAP_KEY_BASE))
			{
			t = &result->ldc_base;
			}
		else if (!strcmp(k, NSS_LDAP_KEY_BINDDN))
			{
			t = &result->ldc_binddn;
			}
		else if (!strcmp(k, NSS_LDAP_KEY_BINDPW))
			{
			t = &result->ldc_bindpw;
			}
		else if (!strcmp(k, NSS_LDAP_KEY_CRYPT))
			{
			if (!strcmp(v, "md5"))
				{
				_nss_ldap_crypt_prefix = MD5_CRYPT;
				}
			else if (!strcmp(v, "sha"))
				{
				_nss_ldap_crypt_prefix = SHA_CRYPT;
				}
			else if (!strcmp(v, "des"))
				{
				_nss_ldap_crypt_prefix = UNIX_CRYPT;
				}
			}
		else if (!strcmp(k, NSS_LDAP_KEY_SCOPE))
			{
			if (!strcmp(v, "sub"))
				{
				result->ldc_scope = LDAP_SCOPE_SUBTREE;
				}
			else if (!strcmp(v, "one"))
				{
				result->ldc_scope = LDAP_SCOPE_ONELEVEL;
				}
			else if (!strcmp(v, "base"))
				{
				result->ldc_scope = LDAP_SCOPE_BASE;
				}
			}
		else if (!strcmp(k, NSS_LDAP_KEY_PORT))
			{
			result->ldc_port = atoi(v);
			}

		if (t != NULL)
			{
			strncpy(p, v, len);
			p[len] = '\0';
			*t = p;
			p += len + 1;
			}
		}

	fclose(fp);

	if (result->ldc_host == NULL || result->ldc_base == NULL)
		{
		return NSS_NOTFOUND;
		}

	return stat;
}

