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

static NSS_STATUS _nss_ldap_getrdnvalue_impl (const char *dn,
					      const char *rdntype,
					      char **rval, char **buffer,
					      size_t * buflen);

#ifdef RFC2307BIS
#ifdef GNU_NSS
#define DN2UID_CACHE
#endif /* GNU_NSS */

#ifdef DN2UID_CACHE
#include <db.h>
#include <fcntl.h>
static DB *__cache = NULL;
#ifdef SUN_NSS
static mutex_t __cache_mutex = DEFAULTMUTEX;
#define cache_lock()	mutex_lock(&__cache_mutex)
#define cache_unlock()	mutex_unlock(&__cache_mutex)
#else
static pthread_mutex_t __cache_mutex = PTHREAD_MUTEX_INITIALIZER;
#define cache_lock()	__libc_lock_lock(__cache_mutex)
#define cache_unlock()	__libc_lock_unlock(__cache_mutex)
#endif /* SUN_NSS */

static NSS_STATUS
dn2uid_cache_put (const char *dn, const char *uid)
{
  DBT key, val;
  int rc;

  cache_lock ();

  if (__cache == NULL)
    {
      __cache = dbopen (NULL, O_RDWR, 0600, DB_HASH, NULL);
      if (__cache == NULL)
	{
	  cache_unlock ();
	  return NSS_TRYAGAIN;
	}
    }
  key.data = (void *) dn;
  key.size = strlen (dn);
  val.data = (void *) uid;
  val.size = strlen (uid);
  rc = (__cache->put) (__cache, &key, &val, 0);

  cache_unlock ();
  return rc ? NSS_TRYAGAIN : NSS_SUCCESS;
}

static NSS_STATUS
dn2uid_cache_get (const char *dn, char **uid, char **buffer, size_t * buflen)
{
  DBT key, val;

  cache_lock ();

  if (__cache == NULL)
    {
      cache_unlock ();
      return NSS_NOTFOUND;
    }

  key.data = (void *) dn;
  key.size = strlen (dn);

  if ((__cache->get) (__cache, &key, &val, 0) != 0)
    {
      cache_unlock ();
      return NSS_NOTFOUND;
    }
  if ((val.size + 1) > *buflen)
    {
      cache_unlock ();
      return NSS_NOTFOUND;
    }

  *uid = *buffer;
  strncpy (*uid, (char *) val.data, val.size);
  (*uid)[val.size] = '\0';
  *buffer += val.size + 1;
  *buflen -= val.size + 1;

  cache_unlock ();
  return NSS_SUCCESS;
}
#endif /* DN2UID_CACHE */

NSS_STATUS
_nss_ldap_dn2uid (LDAP * ld,
		  const char *dn, char **uid, char **buffer, size_t * buflen)
{
  NSS_STATUS status;

  debug ("==> _nss_ldap_dn2uid");

  status = _nss_ldap_getrdnvalue_impl (dn, "uid", uid, buffer, buflen);
  if (status != NSS_SUCCESS)
    {
#ifdef DN2UID_CACHE
      status = dn2uid_cache_get (dn, uid, buffer, buflen);
      if (status != NSS_SUCCESS)
	{
#endif /* DN2UID_CACHE */
	  const char *attrs[] =
	  {"uid", NULL};
	  LDAPMessage *res = _nss_ldap_read (dn, attrs);
	  status = NSS_NOTFOUND;
	  if (res != NULL)
	    {
	      LDAPMessage *e = ldap_first_entry (ld, res);
	      if (e != NULL)
		{
		  status =
		    _nss_ldap_assign_attrval (ld, e, "uid", uid, buffer,
					      buflen);
#ifdef DN2UID_CACHE
		  if (status == NSS_SUCCESS)
		    dn2uid_cache_put (dn, *uid);
		}
#endif /* DN2UID_CACHE */
	    }
	  ldap_msgfree (res);
	}
    }

  debug ("<== _nss_ldap_dn2uid");

  return status;
}
#endif /* RFC2307BIS */

NSS_STATUS
_nss_ldap_getrdnvalue (LDAP * ld,
		       LDAPMessage * entry,
		       const char *rdntype,
		       char **rval, char **buffer, size_t * buflen)
{
  char *dn;
  NSS_STATUS status;

  dn = ldap_get_dn (ld, entry);
  if (dn == NULL)
    {
      return NSS_NOTFOUND;
    }

  status = _nss_ldap_getrdnvalue_impl (dn, rdntype, rval, buffer, buflen);
#ifdef LDAP_VERSION3_API
  ldap_memfree (dn);
#else
  free (dn);
#endif /* LDAP_VERSION3_API */

  /*
   * If examining the DN failed, then pick the nominal first
   * value of cn as the canonical name (recall that attributes
   * are sets, not sequences)
   */
  if (status == NSS_NOTFOUND)
    {
      char **vals;

      vals = ldap_get_values (ld, entry, rdntype);

      if (vals != NULL)
	{
	  int rdnlen = strlen (*vals);
	  if (*buflen >= rdnlen)
	    {
	      char *rdnvalue = *buffer;
	      strncpy (rdnvalue, *vals, rdnlen);
	      rdnvalue[rdnlen] = '\0';
	      *buffer += rdnlen + 1;
	      *buflen -= rdnlen + 1;
	      *rval = rdnvalue;
	      status = NSS_SUCCESS;
	    }
	  else
	    {
	      status = NSS_TRYAGAIN;
	    }
	  ldap_value_free (vals);
	}
    }

  return status;
}

NSS_STATUS
_nss_ldap_getrdnvalue_impl (const char *dn,
			    const char *rdntype,
			    char **rval, char **buffer, size_t * buflen)
{
  char **exploded_dn;
  char *rdnvalue = NULL;
  char rdnava[64];
  int rdnlen = 0, rdnavalen;

  snprintf (rdnava, sizeof rdnava, "%s=", rdntype);
  rdnavalen = strlen (rdnava);

  exploded_dn = ldap_explode_dn (dn, 0);

  if (exploded_dn != NULL)
    {
      /*
       * attempt to get the naming attribute's principal
       * value by parsing the RDN. We need to support
       * multivalued RDNs (as they're essentially mandated
       * for services)
       */
#ifdef LDAP_VERSION3_API
      /*
       * use ldap_explode_rdn() API, as it's cleaner than
       * strtok(). This code has not been tested!
       */
      char **p, **exploded_rdn;

      exploded_rdn = ldap_explode_rdn (*exploded_dn, 0);
      if (exploded_rdn != NULL)
	{
	  for (p = exploded_rdn; *p != NULL; p++)
	    {
	      if (strncasecmp (*p, rdnava, rdnavalen) == 0)
		{
		  char *r = *p + rdnavalen;

		  rdnlen = strlen (r);
		  if (*buflen < rdnlen)
		    {
		      ldap_value_free (exploded_rdn);
		      ldap_value_free (exploded_dn);
		      return NSS_TRYAGAIN;
		    }
		  rdnvalue = *buffer;
		  strncpy (rdnvalue, r, rdnlen);
		  break;
		}
	    }
	  ldap_value_free (exploded_rdn);
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
      for (p = strtok (r, "+");
#else
      for (p = strtok_r (r, "+", &st);
#endif
	   p != NULL;
#ifndef HAVE_STRTOK_R
	   p = strtok (NULL, "+"))
#else
	   p = strtok_r (NULL, "+", &st))
#endif
      {
	if (strncasecmp (p, rdnava, rdnavalen) == 0)
	  {
	    p += rdnavalen;
	    rdnlen = strlen (p);
	    if (*buflen < rdnlen)
	      {
		ldap_value_free (exploded_dn);
		return NSS_TRYAGAIN;
	      }
	    rdnvalue = *buffer;
	    strncpy (rdnvalue, p, rdnlen);
	    break;
	  }
	if (r != NULL)
	  r = NULL;
      }
#endif /* LDAP_VERSION3_API */
    }

  if (exploded_dn != NULL)
    {
      ldap_value_free (exploded_dn);
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

NSS_STATUS
_nss_ldap_readconfig (ldap_config_t ** presult, char *buf, size_t buflen)
{
  FILE *fp;
  char b[NSS_LDAP_CONFIG_BUFSIZ], *p;
  NSS_STATUS stat = NSS_SUCCESS;
  ldap_config_t *result;

  if (*presult == NULL)
    {
      *presult = (ldap_config_t *) malloc (sizeof (*result));
      if (*presult == NULL)
	return NSS_UNAVAIL;
    }

  result = *presult;

  p = buf;

  result->ldc_scope = LDAP_SCOPE_SUBTREE;
  result->ldc_host = NULL;
  result->ldc_base = NULL;
  result->ldc_port = 0;
  result->ldc_binddn = NULL;
  result->ldc_bindpw = NULL;
  result->ldc_rootbinddn = NULL;
  result->ldc_rootbindpw = NULL;
  result->ldc_version = LDAP_VERSION2;
  result->ldc_ssl_on = 0;
  result->ldc_sslpath = NULL;
  result->ldc_next = result;

  fp = fopen (NSS_LDAP_PATH_CONF, "r");
  if (fp == NULL)
    {
      return NSS_UNAVAIL;
    }

  while (fgets (b, sizeof (b), fp) != NULL)
    {
      char *k, *v;
      int len;
      char **t = NULL;

      if (*b == '\n' || *b == '#')
	continue;

      k = b;
      v = k;
      while (*v != '\0' && *v != ' ' && *v != '\t')
	v++;

      if (*v == '\0')
	continue;

      *(v++) = '\0';

      len = strlen (v);

      v[len - 1] = '\0';

      len--;

      if (buflen < (size_t) (len + 1))
	{
	  stat = NSS_TRYAGAIN;
	  break;
	}

      if (!strcasecmp (k, NSS_LDAP_KEY_HOST))
	{
	  t = &result->ldc_host;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_BASE))
	{
	  t = &result->ldc_base;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_BINDDN))
	{
	  t = &result->ldc_binddn;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_BINDPW))
	{
	  t = &result->ldc_bindpw;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_ROOTBINDDN))
	{
	  t = &result->ldc_rootbinddn;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_SSLPATH))
	{
	  t = &result->ldc_sslpath;
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_CRYPT))
	{
	  if (!strcasecmp (v, "md5"))
	    {
	      _nss_ldap_crypt_prefix = MD5_CRYPT;
	    }
	  else if (!strcasecmp (v, "sha"))
	    {
	      _nss_ldap_crypt_prefix = SHA_CRYPT;
	    }
	  else if (!strcasecmp (v, "des"))
	    {
	      _nss_ldap_crypt_prefix = UNIX_CRYPT;
	    }
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_SCOPE))
	{
	  if (!strcasecmp (v, "sub"))
	    {
	      result->ldc_scope = LDAP_SCOPE_SUBTREE;
	    }
	  else if (!strcasecmp (v, "one"))
	    {
	      result->ldc_scope = LDAP_SCOPE_ONELEVEL;
	    }
	  else if (!strcasecmp (v, "base"))
	    {
	      result->ldc_scope = LDAP_SCOPE_BASE;
	    }
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_PORT))
	{
	  result->ldc_port = atoi (v);
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_SSL))
	{
	  result->ldc_ssl_on = !strcasecmp(v, "yes");
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_LDAP_VERSION))
	{
	  result->ldc_version = atoi (v);
	}

      if (t != NULL)
	{
	  strncpy (p, v, len);
	  p[len] = '\0';
	  *t = p;
	  p += len + 1;
	}
    }

  fclose (fp);

  fp = fopen (NSS_LDAP_PATH_ROOTPASSWD, "r");
  if (fp)
    {
      if (fgets (b, sizeof (b), fp) != NULL)
	{
	  int len;

	  len = strlen (b);
	  if (len > 0)
	    len--;

	  strncpy (p, b, len);
	  p[len] = '\0';
	  result->ldc_rootbindpw = p;
	  p += len + 1;
	}
      fclose (fp);
    }
  else
    {
      result->ldc_rootbinddn = NULL;
    }

  if (result->ldc_host == NULL)
    {
      return NSS_NOTFOUND;
    }

  if (result->ldc_port == 0)
    {
#ifdef SSL
      if (result->ldc_ssl_on)
	{
	  result->ldc_port = LDAPS_PORT;
	}
      else
#endif /* SSL */
	result->ldc_port = LDAP_PORT;
    }


  return stat;
}
