/* Copyright (C) 2002-2003 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2002.

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
 * Glue code to support AIX loadable authentication modules.
 */

#include "config.h"

static char rcsId[] =
  "$Id$";

#ifdef AIX

#include <stdlib.h>
#include <string.h>
#include <usersec.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "util.h"

static struct irs_gr *grp_conn = NULL;
static struct irs_pw *pwd_conn = NULL;

/* Prototype definitions */
void *gr_pvtinit (void);
struct group *gr_byname (struct irs_gr *, const char *);
struct group *gr_bygid (struct irs_gr *, gid_t);
void gr_close (struct irs_gr *);

void *pw_pvtinit (void);
struct passwd *pw_byname (struct irs_pw *, const char *);
struct passwd *pw_byuid (struct irs_pw *, uid_t);
void pw_close (struct irs_pw *);

/* from ldap-grp.c */
char *_nss_ldap_getgrset (char *user);

static void *
_nss_ldap_open (const char *name, const char *domain,
		const int mode, char *options)
{
  /* Currently we do not use the above parameters */

  grp_conn = (struct irs_gr *) gr_pvtinit ();
  pwd_conn = (struct irs_pw *) pw_pvtinit ();
  return NULL;
}

static int
_nss_ldap_close (void *token)
{
  gr_close (grp_conn);
  grp_conn = NULL;

  pw_close (pwd_conn);
  pwd_conn = NULL;

  return AUTH_SUCCESS;
}

static struct group *
_nss_ldap_getgrgid (gid_t gid)
{
  if (!grp_conn)
    return NULL;

  return gr_bygid (grp_conn, gid);
}

static struct group *
_nss_ldap_getgrnam (const char *name)
{
  if (!grp_conn)
    return NULL;

  return gr_byname (grp_conn, name);
}

static struct passwd *
_nss_ldap_getpwuid (uid_t uid)
{
  if (!pwd_conn)
    return NULL;

  return pw_byuid (pwd_conn, uid);
}

static struct passwd *
_nss_ldap_getpwnam (const char *name)
{
  if (!pwd_conn)
    return NULL;

  return pw_byname (pwd_conn, name);
}

static struct group *
_nss_ldap_getgracct (void *id, int type)
{
  if (type == SEC_INT)
    return _nss_ldap_getgrgid (*(gid_t *) id);
  else
    return _nss_ldap_getgrnam ((char *) id);
}

int
_nss_ldap_authenticate (char *user, char *response, int *reenter,
			char **message)
{
  NSS_STATUS stat;
  int rc;

  debug ("==> _nss_ldap_authenticate");

  *reenter = FALSE;
  *message = NULL;

  stat = _nss_ldap_proxy_bind (user, response);

  switch (stat)
    {
    case NSS_TRYAGAIN:
      rc = AUTH_FAILURE;
      break;
    case NSS_NOTFOUND:
      rc = AUTH_NOTFOUND;
      break;
    case NSS_SUCCESS:
      rc = AUTH_SUCCESS;
      break;
    default:
    case NSS_UNAVAIL:
      rc = AUTH_UNAVAIL;
      break;
    }

  debug ("<== _nss_ldap_authenticate");

  return rc;
}

/*
 * Support this for when proxy authentication is disabled.
 * There may be some re-entrancy issues here; not sure
 * if we are supposed to return allocated memory or not,
 * this is not documented. I am assuming not in line with
 * the other APIs.
 */
char *
_nss_ldap_getpasswd (char *user)
{
  struct passwd *pw;
  static char pwdbuf[32];
  char *p = NULL;

  debug ("==> _nss_ldap_getpasswd");

  pw = _nss_ldap_getpwnam (user);
  if (pw != NULL)
    {
      if (strlen (pw->pw_passwd) > sizeof (pwdbuf) - 1)
	{
	  errno = ERANGE;
	}
      else
	{
	  strcpy (pwdbuf, pw->pw_passwd);
	  p = pwdbuf;
	}
    }

  debug ("<== _nss_ldap_getpasswd");

  return p;
}

int
nss_ldap_initialize (struct secmethod_table *meths)
{
  memset (meths, 0, sizeof (*meths));

  /* Identification methods */
  meths->method_getpwnam = _nss_ldap_getpwnam;
  meths->method_getpwuid = _nss_ldap_getpwuid;
  meths->method_getgrnam = _nss_ldap_getgrnam;
  meths->method_getgrgid = _nss_ldap_getgrgid;
  meths->method_getgrset = _nss_ldap_getgrset;
  /*
   * These casts are necessary because the prototypes 
   * in the AIX headers are wrong.
   */
  meths->method_getgracct = (int (*)(void *, int))_nss_ldap_getgracct;
  meths->method_getpasswd = (int (*)(char *))_nss_ldap_getpasswd;

  /* Support methods */
  meths->method_open = _nss_ldap_open;
  meths->method_close = _nss_ldap_close;

  /* Authentication method */
  meths->method_authenticate = _nss_ldap_authenticate;

  return AUTH_SUCCESS;
}

#endif /* AIX */

