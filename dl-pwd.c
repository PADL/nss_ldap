
/* Copyright (C) 1997 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.

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

/* an experimental module for IRIX and other ELF operating systems
 * which don't support the NSS to integrate LDAP for resolver calls.
 */

#ifdef DL_NSS

static char rcsId[] = "$Id$";

#include <stdlib.h>
#include <pwd.h>
#include <dlfcn.h>
#include <lber.h>
#include <ldap.h>

#ifdef OSF1
#include <sia.h>
#include <errno.h>
#endif

#include "ldap-nss.h"
#include "dl-pwd.h"
#include "dl-nss.h"
#include "globals.h"

#ifdef OSF1
typedef int (*libc_getpwnam_r_t) (const char *, struct passwd *, char *,
				  size_t, struct passwd **);
typedef int (*libc_getpwuid_r_t) (uid_t, struct passwd *, char *, size_t,
				  struct passwd **);
typedef int (*libc_getpwent_r_t) (struct passwd *, char *, int, FILE **);
typedef int (*libc_setpwent_r_t) (FILE **);
typedef int (*libc_endpwent_r_t) (FILE **);
#endif
typedef struct passwd *(*libc_getpwnam_t) (const char *);
typedef struct passwd *(*libc_getpwuid_t) (uid_t);
typedef struct passwd *(*libc_getpwent_t) (void);
#ifdef OSF1
typedef int (*libc_setpwent_t) (void);
#else
typedef void (*libc_setpwent_t) (void);
#endif
typedef void (*libc_endpwent_t) (void);

#ifdef OSF1
static libc_getpwnam_r_t libc_getpwnam_r = NULL;
static libc_getpwuid_r_t libc_getpwuid_r = NULL;
static libc_setpwent_r_t libc_setpwent_r = NULL;
static libc_endpwent_r_t libc_endpwent_r = NULL;
static libc_getpwent_r_t libc_getpwent_r = NULL;
#endif
static libc_getpwnam_t libc_getpwnam = NULL;
static libc_getpwuid_t libc_getpwuid = NULL;
static libc_setpwent_t libc_setpwent = NULL;
static libc_endpwent_t libc_endpwent = NULL;
static libc_getpwent_t libc_getpwent = NULL;

#ifdef OSF1
static char nss_buf[SIABUFSIZ] =
{'\0'};
#else
static char nss_buf[NSS_BUFLEN_PASSWD] =
{'\0'};
#endif

static int do_ldap_getpwent = 0;

#ifdef OSF1
/* this is the OSF/1 interface, anyway. Disgusting. The "right" way is
 * to use SIA. Oh well. Don't think this is threadsafe.
 */
int
getpwent_r (struct passwd *pw, char *buffer, int len, FILE ** pw_fp)
{
  /* returns 0 or errno */
  NSS_STATUS status;

  if (do_ldap_getpwent == 0)
    {
      INIT_HANDLE ();
      if (libc_getpwent_r == NULL)
	{
	  libc_getpwent_r =
	    (libc_getpwent_r_t) dlsym (_nss_ldap_libc_handle, "getpwent_r");
	}
      if (libc_getpwent_r == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}
      if (libc_getpwent_r (pw, buffer, len, pw_fp) == 0)
	{
	  return 0;
	}
      if (libc_endpwent_r == NULL)
	{
	  libc_endpwent_r =
	    (libc_endpwent_r_t) dlsym (_nss_ldap_libc_handle, "endpwent_r");
	}
      if (libc_endpwent_r == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}
      libc_endpwent_r (pw_fp);
      if (_nss_ldap_setpwent_r () != NSS_SUCCESS)
	{
	  errno = EINVAL;
	  return -1;
	}
      do_ldap_getpwent = 1;
    }

  status = _nss_ldap_getpwent_r (pw, buffer, (size_t) len);
  switch (status)
    {
    case NSS_TRYAGAIN:
      errno = ERANGE;
      return -1;
    case NSS_NOTFOUND:
      errno = ENOENT;
      return -1;
    default:
      errno = ESUCCESS;
    }

  return 0;
}
#endif

struct passwd *
getpwent (void)
{
  static struct passwd pw;

  if (do_ldap_getpwent == 0)
    {
      struct passwd *p;

      INIT_HANDLE ();

      if (libc_getpwent == NULL)
	{
	  libc_getpwent =
	    (libc_getpwent_t) dlsym (_nss_ldap_libc_handle, "getpwent");
	}
      if (libc_getpwent == NULL)
	{
	  return NULL;
	}

      p = libc_getpwent ();
      if (p == NULL)
	{
	  if (libc_endpwent == NULL)
	    {
	      libc_endpwent =
		(libc_endpwent_t) dlsym (_nss_ldap_libc_handle, "endpwent");
	    }
	  if (libc_endpwent == NULL)
	    {
	      return NULL;
	    }
	  libc_endpwent ();
	  if (_nss_ldap_setpwent_r () != NSS_SUCCESS)
	    {
	      return NULL;
	    }
	  do_ldap_getpwent = 1;
	}
      else
	{
	  return p;
	}
    }

  if (_nss_ldap_getpwent_r (&pw, nss_buf, sizeof (nss_buf)) == NSS_SUCCESS)
    return &pw;

  return NULL;
}

#ifdef OSF1
/* XXX we should implement the non-Posix one as well, but I can't be bothered.
 * That doesn't take the last argument, and has a symbol name of getpwuid_r instead
 * of Pgetpwuid_r. Ditto for getpwnam.
 */
int
getpwuid_r (uid_t uid, struct passwd *pwd, char *buffer, size_t len,
	    struct passwd **result)
{
  NSS_STATUS status;
  INIT_HANDLE ();

  if (libc_getpwuid_r == NULL)
    {
      libc_getpwuid_r =
	(libc_getpwuid_r_t) dlsym (_nss_ldap_libc_handle, "getpwuid_r");
    }
  if (libc_getpwuid_r == NULL)
    {
      return EINVAL;
    }

  if (libc_getpwuid_r (uid, pwd, buffer, len, result) == ESUCCESS)
    {
      return ESUCCESS;
    }

  status = _nss_ldap_getpwuid_r (uid, pwd, buffer, len);
  switch (status)
    {
    case NSS_TRYAGAIN:
      *result = NULL;
      return ERANGE;
    case NSS_UNAVAIL:
      *result = NULL;
      return ENOENT;
    default:
      *result = pwd;
    }
  return ESUCCESS;
}
#endif

struct passwd *
getpwuid (uid_t uid)
{
  static struct passwd pw;
  struct passwd *p;

  INIT_HANDLE ();

  if (libc_getpwuid == NULL)
    {
      libc_getpwuid =
	(libc_getpwuid_t) dlsym (_nss_ldap_libc_handle, "getpwuid");
    }
  if (libc_getpwuid == NULL)
    {
      return NULL;
    }

  p = libc_getpwuid (uid);

  if (p != NULL)
    {
      return p;
    }
  if (_nss_ldap_getpwuid_r (uid, &pw, nss_buf, sizeof (nss_buf)) ==
      NSS_SUCCESS)
    {
      return &pw;
    }
  return NULL;
}

#ifdef OSF1
int
getpwnam_r (const char *name, struct passwd *pwd, char *buffer, size_t len,
	    struct passwd **result)
{
  NSS_STATUS status;
  INIT_HANDLE ();

  if (libc_getpwnam_r == NULL)
    {
      libc_getpwnam_r =
	(libc_getpwnam_r_t) dlsym (_nss_ldap_libc_handle, "getpwnam_r");
    }
  if (libc_getpwnam_r == NULL)
    {
      return EINVAL;
    }

  if (libc_getpwnam_r (name, pwd, buffer, len, result) == ESUCCESS)
    {
      return ESUCCESS;
    }

  status = _nss_ldap_getpwnam_r (name, pwd, buffer, len);
  switch (status)
    {
    case NSS_TRYAGAIN:
      *result = NULL;
      return ERANGE;
    case NSS_UNAVAIL:
      *result = NULL;
      return ENOENT;
    default:
      *result = pwd;
    }
  return ESUCCESS;
}
#endif

struct passwd *
getpwnam (const char *name)
{
  static struct passwd pw;
  struct passwd *p;

  INIT_HANDLE ();

  if (libc_getpwnam == NULL)
    {
      libc_getpwnam =
	(libc_getpwnam_t) dlsym (_nss_ldap_libc_handle, "getpwnam");
    }
  if (libc_getpwnam == NULL)
    {
      return NULL;
    }

  p = libc_getpwnam (name);

  if (p != NULL)
    {
      return p;
    }

  if (_nss_ldap_getpwnam_r (name, &pw, nss_buf, sizeof (nss_buf)) ==
      NSS_SUCCESS)
    {
      return &pw;
    }

  return NULL;
}

#ifdef OSF1
int
setpwent_r (FILE ** fp)
{
  do_ldap_getpwent = 0;
  INIT_HANDLE ();
  if (libc_setpwent_r == NULL)
    {
      libc_setpwent_r =
	(libc_setpwent_r_t) dlsym (_nss_ldap_libc_handle, "setpwent_r");
    }
  if (libc_setpwent_r != NULL)
    {
      return libc_setpwent_r (fp);
    }
  return EINVAL;
}
#endif

#ifdef OSF1
int
setpwent (void)
#else
void
setpwent (void)
#endif
{
  do_ldap_getpwent = 0;
  INIT_HANDLE ();
  if (libc_setpwent == NULL)
    {
      libc_setpwent =
	(libc_setpwent_t) dlsym (_nss_ldap_libc_handle, "setpwent");
    }
  if (libc_setpwent != NULL)
    {
#ifdef OSF1
      return libc_setpwent ();
#else
      libc_setpwent ();
#endif
    }
}

#ifdef OSF1
void
endpwent_r (FILE ** fp)
{
  if (do_ldap_getpwent == 0)
    {
      INIT_HANDLE ();
      if (libc_endpwent_r == NULL)
	{
	  libc_endpwent_r =
	    (libc_endpwent_r_t) dlsym (_nss_ldap_libc_handle, "endpwent_r");
	}
      if (libc_endpwent_r != NULL)
	{
	  libc_endpwent_r (fp);
	}
    }
  else
    {
      (void) _nss_ldap_endpwent_r ();
    }
}
#endif

void
endpwent (void)
{
  if (do_ldap_getpwent == 0)
    {
      INIT_HANDLE ();
      if (libc_endpwent == NULL)
	{
	  libc_endpwent =
	    (libc_endpwent_t) dlsym (_nss_ldap_libc_handle, "endpwent");
	}
      if (libc_endpwent != NULL)
	{
	  libc_endpwent ();
	}
    }
  else
    {
      (void) _nss_ldap_endpwent_r ();
    }

  do_ldap_getpwent = 0;
}

#endif /* DL_NSS */
