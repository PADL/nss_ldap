/* Copyright (C) 1997-2001 Luke Howard.
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>

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
#include "globals.h"
#include "util.h"

static char rcsId[] = "$Id$";

static NSS_STATUS do_getrdnvalue (const char *dn,
				  const char *rdntype,
				  char **rval, char **buffer,
				  size_t * buflen);

static NSS_STATUS do_searchdescriptorconfig (const char *key,
					     const char *value,
					     size_t valueLength,
					     ldap_service_search_descriptor_t
					     ** result, char **buffer,
					     size_t * buflen);

/*
 * Use db_185.h first, as that's an old DB wrapper
 * around DB 2.x. If we don't have that, use db1/db.h,
 * which I think may me the original DB library.
 * Last resort, use db.h, which we hope has the
 * right API!
 */
#ifdef RFC2307BIS
#ifdef HAVE_DB_185_H
#include <db_185.h>
#define DN2UID_CACHE
#elif defined(HAVE_DB1_DB_H)
#include <db1/db.h>
#define DN2UID_CACHE
#elif defined(HAVE_DB_H)
#include <db.h>
#define DN2UID_CACHE
#endif /* HAVE_DB1_DB_H */

#ifdef DN2UID_CACHE
#include <fcntl.h>
static DB *__cache = NULL;

#ifdef HAVE_THREAD_H
static mutex_t __cache_mutex = DEFAULTMUTEX;
#define cache_lock()      mutex_lock(&__cache_mutex)
#define cache_unlock()    mutex_unlock(&__cache_mutex)
#elif defined(HAVE_PTHREAD_H)
static pthread_mutex_t __cache_mutex = PTHREAD_MUTEX_INITIALIZER;
#if defined(HAVE_LIBC_LOCK_H) || defined(HAVE_BITS_LIBC_LOCK_H)
#define cache_lock()     __libc_lock_lock(__cache_mutex)
#define cache_unlock()   __libc_lock_unlock(__cache_mutex)
#else
#define cache_lock()     pthread_mutex_lock(&__cache_mutex)
#define cache_unlock()   pthread_mutex_unlock(&__cache_mutex)
#endif /* HAVE_LIBC_LOCK_H || HAVE_BITS_LIBC_LOCK_H */
#else
#define cache_lock()
#define cache_unlock()
#endif /* HAVE_THREAD_H */

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

  status = do_getrdnvalue (dn, "uid", uid, buffer, buflen);
  if (status != NSS_SUCCESS)
    {
#ifdef DN2UID_CACHE
      status = dn2uid_cache_get (dn, uid, buffer, buflen);
      if (status != NSS_SUCCESS)
	{
#endif /* DN2UID_CACHE */
	  const char *attrs[] =
	  {"uid", NULL};
	  LDAPMessage *res;

	  status = NSS_NOTFOUND;

	  if (_nss_ldap_read (dn, attrs, &res) == NSS_SUCCESS)
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

  status = do_getrdnvalue (dn, rdntype, rval, buffer, buflen);
#ifdef HAVE_LDAP_MEMFREE
  ldap_memfree (dn);
#else
  free (dn);
#endif /* HAVE_LDAP_MEMFREE */

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
do_getrdnvalue (const char *dn,
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
#ifdef HAVE_LDAP_EXPLODE_RDN
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
#endif /* HAVE_LDAP_EXPLODE_RDN */
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

static NSS_STATUS
do_searchdescriptorconfig (const char *key, const char *value, size_t len,
			   ldap_service_search_descriptor_t ** result,
			   char **buffer, size_t * buflen)
{
  ldap_service_search_descriptor_t **t;
  char *base;
  char *filter, *s;
  int scope;

  t = NULL;
  filter = NULL;
  scope = -1;

  if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_PASSWD))
    t = &result[LM_PASSWD];
  if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_SHADOW))
    t = &result[LM_SHADOW];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_GROUP))
    t = &result[LM_GROUP];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_HOSTS))
    t = &result[LM_HOSTS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_SERVICES))
    t = &result[LM_SERVICES];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_NETWORKS))
    t = &result[LM_NETWORKS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_PROTOCOLS))
    t = &result[LM_PROTOCOLS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_RPC))
    t = &result[LM_RPC];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_ETHERS))
    t = &result[LM_ETHERS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_NETMASKS))
    t = &result[LM_NETMASKS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_BOOTPARAMS))
    t = &result[LM_BOOTPARAMS];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_ALIASES))
    t = &result[LM_ALIASES];
  else if (!strcasecmp (key, NSS_LDAP_KEY_NSS_BASE_NETGROUP))
    t = &result[LM_NETGROUP];

  if (t == NULL)
    return NSS_SUCCESS;

  /* we have already checked for room for the value */
  /* len is set to the length of value */
  base = *buffer;
  strncpy (base, value, len);
  base[len] = '\0';

  *buffer += len + 1;
  *buflen -= len + 1;

  /* probably is some funky escaping needed here. later... */
  s = strchr (base, '?');
  if (s != NULL)
    {
      *s = '\0';
      s++;
      if (!strcasecmp (s, "sub"))
	scope = LDAP_SCOPE_SUBTREE;
      else if (!strcasecmp (s, "one"))
	scope = LDAP_SCOPE_ONELEVEL;
      else if (!strcasecmp (s, "base"))
	scope = LDAP_SCOPE_BASE;
      filter = strchr (s, '?');
      if (filter != NULL)
	{
	  *filter = '\0';
	  filter++;
	}
    }

  if (bytesleft (*buffer, *buflen, ldap_service_search_descriptor_t) < sizeof (ldap_service_search_descriptor_t))
    return NSS_UNAVAIL;

  align (*buffer, *buflen, ldap_service_search_descriptor_t);

  *t = (ldap_service_search_descriptor_t *) * buffer;

  (*t)->lsd_base = base;
  (*t)->lsd_scope = scope;
  (*t)->lsd_filter = filter;

  *buffer += sizeof (ldap_service_search_descriptor_t);
  *buflen -= sizeof (ldap_service_search_descriptor_t);

  return NSS_SUCCESS;
}

NSS_STATUS
_nss_ldap_readconfig (ldap_config_t ** presult, char *buffer, size_t buflen)
{
  FILE *fp;
  char b[NSS_LDAP_CONFIG_BUFSIZ];
  NSS_STATUS stat = NSS_SUCCESS;
  ldap_config_t *result;

  if (*presult == NULL)
    {
      *presult = (ldap_config_t *) calloc (1, sizeof (*result));
      if (*presult == NULL)
	return NSS_UNAVAIL;
    }

  result = *presult;

  result->ldc_scope = LDAP_SCOPE_SUBTREE;
  result->ldc_deref = LDAP_DEREF_NEVER;
  result->ldc_host = NULL;
  result->ldc_base = NULL;
  result->ldc_port = 0;
  result->ldc_binddn = NULL;
  result->ldc_bindpw = NULL;
  result->ldc_rootbinddn = NULL;
  result->ldc_rootbindpw = NULL;
#ifdef LDAP_VERSION3
  result->ldc_version = LDAP_VERSION3;
#else
  result->ldc_version = LDAP_VERSION2;
#endif /* LDAP_VERSION3 */
  result->ldc_timelimit = LDAP_NO_LIMIT;
  result->ldc_bind_timelimit = 30;
  result->ldc_ssl_on = SSL_OFF;
  result->ldc_sslpath = NULL;
  result->ldc_referrals = 1;
  result->ldc_restart = 1;
  result->ldc_next = result;

  fp = fopen (NSS_LDAP_PATH_CONF, "r");
  if (fp == NULL)
    {
      free (result);
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

      /* skip past all characters in keyword */
      while (*v != '\0' && *v != ' ' && *v != '\t')
	v++;

      if (*v == '\0')
	continue;

      /* terminate keyword */
      *(v++) = '\0';

      /* skip all whitespaces between keyword and value */
      /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
      while (*v == ' ' || *v == '\t')
	v++;

      len = strlen (v);

      v[len - 1] = '\0';

      len--;

      if (buflen < (size_t) (len + 1))
	{
	  /*
	   * fix in nss_ldap-127: don't return NSS_TRYAGAIN,
	   * as we have no way to increase the buffer size.
	   */
	  stat = NSS_UNAVAIL;
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
      else if (!strcasecmp (k, NSS_LDAP_KEY_DEREF))
	{
	  if (!strcasecmp (v, "never"))
	    {
	      result->ldc_deref = LDAP_DEREF_NEVER;
	    }
	  else if (!strcasecmp (v, "searching"))
	    {
	      result->ldc_deref = LDAP_DEREF_SEARCHING;
	    }
	  else if (!strcasecmp (v, "finding"))
	    {
	      result->ldc_deref = LDAP_DEREF_FINDING;
	    }
	  else if (!strcasecmp (v, "always"))
	    {
	      result->ldc_deref = LDAP_DEREF_ALWAYS;
	    }
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_PORT))
	{
	  result->ldc_port = atoi (v);
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_SSL))
	{
	  if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
	      || !strcasecmp (v, "true"))
	    {
	      result->ldc_ssl_on = SSL_LDAPS;
	    }
	  else if (!strcasecmp (v, "start_tls"))
	    {
	      result->ldc_ssl_on = SSL_START_TLS;
	    }
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_REFERRALS))
	{
	  result->ldc_referrals = (!strcasecmp (v, "on")
				   || !strcasecmp (v, "yes")
				   || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_RESTART))
	{
	  result->ldc_restart = (!strcasecmp (v, "on")
				 || !strcasecmp (v, "yes")
				 || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_LDAP_VERSION))
	{
	  result->ldc_version = atoi (v);
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_TIMELIMIT))
	{
	  result->ldc_timelimit = atoi (v);
	}
      else if (!strcasecmp (k, NSS_LDAP_KEY_BIND_TIMELIMIT))
	{
	  result->ldc_bind_timelimit = atoi (v);
	}
      else
	{
	  /*
	   * check whether the key is a naming context key
	   * if yes, parse; otherwise just return NSS_SUCCESS
	   * so we can ignore keys we don't understand.
	   */
	  stat =
	    do_searchdescriptorconfig (k, v, len, result->ldc_sds, &buffer,
				       &buflen);
	  if (stat == NSS_UNAVAIL)
	    {
	      break;
	    }
	}

      if (t != NULL)
	{
	  strncpy (buffer, v, len);
	  buffer[len] = '\0';
	  *t = buffer;
	  buffer += len + 1;
	  /* fix in nss_ldap-127: decrement buflen */
	  buflen -= len + 1;
	}
    }

  fclose (fp);

  /*
   * fix in nss_ldap-127: return if out of buffer space
   */
  if (stat != NSS_SUCCESS)
    {
      free (result);
      return stat;
    }

  if (result->ldc_rootbinddn != NULL)
    {
      fp = fopen (NSS_LDAP_PATH_ROOTPASSWD, "r");
      if (fp)
	{
	  if (fgets (b, sizeof (b), fp) != NULL)
	    {
	      int len;

	      len = strlen (b);
	      if (len > 0)
		len--;

	      /* fix in nss_ldap-127: check for enough buffer space */
	      if (buflen < (size_t) (len + 1))
		{
		  free (result);
		  return NSS_UNAVAIL;
		}

	      strncpy (buffer, b, len);
	      buffer[len] = '\0';
	      result->ldc_rootbindpw = buffer;
	      buffer += len + 1;
	      /* fix in nss_ldap-127: decrement buflen */
	      buflen -= len + 1;
	    }
	  fclose (fp);
	}
      else
	{
	  result->ldc_rootbinddn = NULL;
	}
    }

  if (result->ldc_host == NULL)
    {
      free (result);
      return NSS_NOTFOUND;
    }

  if (result->ldc_port == 0)
    {
#ifdef LDAPS_PORT
      if (result->ldc_ssl_on == SSL_LDAPS)
	{
	  result->ldc_port = LDAPS_PORT;
	}
      else
#endif /* SSL */
	result->ldc_port = LDAP_PORT;
    }

  return stat;
}

NSS_STATUS
_nss_ldap_escape_string (const char *str, char *buf, size_t buflen)
{
  int ret = NSS_TRYAGAIN;
  char *p = buf;
  char *limit = p + buflen - 3;
  const char *s = str;

  while (p < limit && *s)
    {
      switch (*s)
	{
	case '*':
	  strcpy (p, "\\2a");
	  p += 3;
	  break;
	case '(':
	  strcpy (p, "\\28");
	  p += 3;
	  break;
	case ')':
	  strcpy (p, "\\29");
	  p += 3;
	  break;
	case '\\':
	  strcpy (p, "\\5c");
	  p += 3;
	  break;
	default:
	  *p++ = *s;
	  break;
	}
      s++;
    }

  if (*s == '\0')
    {
      /* got to end */
      *p = '\0';
      ret = NSS_SUCCESS;
    }

  return ret;
}
