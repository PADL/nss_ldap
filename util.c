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

#include "ldap-nss.h"
#include "globals.h"
#include "util.h"

static char rcsId[] = "$Id$";

NSS_STATUS _nss_ldap_getrdnvalue(
	LDAP *ld,
	LDAPMessage *entry,
	char **rval,
	char **buffer,
	size_t *buflen)
{

	/*
	 * should getrdnvalue() take a parameterized RDN attribute type?
	 * or is it safe to assume the cn is the only multivalued attribute
	 * we'll need to canonicalize on??
	 */

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
		/*
		 * attempt to get the naming attribute's principal
		 * value by parsing the RDN. We need to support
		 * multivalued RDNs (as they're essentially mandated
		 * for services)
		 */
#ifdef NETSCAPE_SDK
		/*
		 * use ldap_explode_rdn() API, as it's cleaner than
		 * strtok(). This code has not been tested!
		 */
		char **p, **exploded_rdn;

		exploded_rdn = ldap_explode_rdn(*exploded_dn, 0);
		if (exploded_rdn != NULL)
			{
			for (p = exploded_rdn; *p != NULL; p++)
				{
				if (strncasecmp(*p, CN_ATTR_AVA, CN_ATTR_AVA_LEN) == 0)
					{
					char *r = *p + CN_ATTR_AVA_LEN;

					rdnlen = strlen(r);
					if (*buflen < rdnlen)
						{
						ldap_memfree(dn);
						ldap_value_free(exploded_rdn);
						ldap_value_free(exploded_dn);
						return NSS_TRYAGAIN;
						}
					rdnvalue = *buffer;
					strncpy(rdnvalue, r, rdnlen);
					break;
					}
				}
			ldap_value_free(exploded_rdn);
			}
#else
		/*
		 * we don't have Netscape's ldap_explode_rdn() API,
		 * so we fudge it with strtok(). Note that this will
		 * not handle escaping properly.
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
					free(dn);
					ldap_value_free(exploded_dn);
					return NSS_TRYAGAIN;
					}
				rdnvalue = *buffer;
				strncpy(rdnvalue, p, rdnlen);
				break;
				}
			if (r != NULL)
				r = NULL;
			}
#endif /* NETSCAPE_SDK */
		}

	/*
	 * If examining the DN failed, then pick the nominal first
	 * value of cn as the canonical name (recall that attributes
	 * are sets, not sequences)
	 */
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
#else
	free(dn);
#endif

	if (exploded_dn != NULL)
		{
		ldap_value_free(exploded_dn);
		}

	if (rdnvalue != NULL)
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
        ldap_config_t **presult,
        char *buf,
        size_t buflen
)
{
	FILE *fp;
	char b[NSS_LDAP_CONFIG_BUFSIZ], *p;
	NSS_STATUS stat = NSS_SUCCESS;
	ldap_config_t *result;

	if (*presult == NULL)
		{
		*presult = (ldap_config_t *)malloc(sizeof(*result));
		if (*presult == NULL)
			return NSS_UNAVAIL;
		}

	result = *presult;

	p = buf;

	result->ldc_scope = LDAP_SCOPE_SUBTREE;
	result->ldc_host = NULL;
	result->ldc_base = NULL;
	result->ldc_port = LDAP_PORT;
	result->ldc_binddn = NULL;
	result->ldc_bindpw = NULL;
	result->ldc_version = LDAP_VERSION2;
	result->ldc_next = result;

	fp = fopen(NSS_LDAP_PATH_CONF, "r");
	if (fp == NULL)
		{
		return NSS_UNAVAIL;
		}

	while(fgets(b, sizeof(b), fp) != NULL)
		{
		char *k, *v;
		int len;
		char **t = NULL;

		if (*b == '\n' || *b == '#')
			continue;

		k = b;
		v = strchr(k, ' ');
		if (v == NULL)
			v = strchr(k, '\t');

		if (v == NULL)
			continue;

		*(v++) = '\0';

		len = strlen(v);

		v[len - 1] = '\0';

		len--;

		if (buflen < (size_t)(len + 1))
			{
			stat = NSS_TRYAGAIN;
			break;
			}

		if (!strcasecmp(k, NSS_LDAP_KEY_HOST))
			{
			t = &result->ldc_host;
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_BASE))
			{
			t = &result->ldc_base;
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_BINDDN))
			{
			t = &result->ldc_binddn;
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_BINDPW))
			{
			t = &result->ldc_bindpw;
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_CRYPT))
			{
			if (!strcasecmp(v, "md5"))
				{
				_nss_ldap_crypt_prefix = MD5_CRYPT;
				}
			else if (!strcasecmp(v, "sha"))
				{
				_nss_ldap_crypt_prefix = SHA_CRYPT;
				}
			else if (!strcasecmp(v, "des"))
				{
				_nss_ldap_crypt_prefix = UNIX_CRYPT;
				}
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_SCOPE))
			{
			if (!strcasecmp(v, "sub"))
				{
				result->ldc_scope = LDAP_SCOPE_SUBTREE;
				}
			else if (!strcasecmp(v, "one"))
				{
				result->ldc_scope = LDAP_SCOPE_ONELEVEL;
				}
			else if (!strcasecmp(v, "base"))
				{
				result->ldc_scope = LDAP_SCOPE_BASE;
				}
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_PORT))
			{
			result->ldc_port = atoi(v);
			}
		else if (!strcasecmp(k, NSS_LDAP_KEY_LDAP_VERSION))
			{
			result->ldc_version = atoi(v);
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

	if (result->ldc_host == NULL)
		{
		return NSS_NOTFOUND;
		}

	return stat;
}

