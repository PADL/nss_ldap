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

/*
 * an experimental module for IRIX and other ELF operating systems
 * which don't support the NSS to integrate LDAP for resolver calls.
 */

#ifdef DL_NSS

static char rcsId[] = "$Id$";

#include <stdlib.h>
#include <grp.h>
#include <dlfcn.h>
#include <lber.h>
#include <ldap.h>

#ifdef OSF1
#include <sia.h>
#include <errno.h>
#endif

#include "ldap-nss.h"
#include "dl-grp.h"
#include "dl-nss.h"
#include "globals.h"

#ifdef OSF1
typedef int (*libc_getgrnam_r_t) (const char *, struct group *, char *,
				  size_t, struct group **);
typedef int (*libc_getgrgid_r_t) (gid_t, struct group *, char *, size_t,
				  struct group **);
typedef int (*libc_getgrent_r_t) (struct group *, char *, int, FILE **);
typedef int (*libc_setgrent_r_t) (FILE **);
typedef int (*libc_endgrent_r_t) (FILE **);
#endif
typedef struct group *(*libc_getgrnam_t) (const char *);
typedef struct group *(*libc_getgrgid_t) (gid_t);
typedef struct group *(*libc_getgrent_t) (void);
#ifdef OSF1
typedef int (*libc_setgrent_t) (void);
#else
typedef void (*libc_setgrent_t) (void);
#endif
typedef void (*libc_endgrent_t) (void);

#ifdef OSF1
static libc_getgrnam_r_t libc_getgrnam_r = NULL;
static libc_getgrgid_r_t libc_getgrgid_r = NULL;
static libc_setgrent_r_t libc_setgrent_r = NULL;
static libc_endgrent_r_t libc_endgrent_r = NULL;
static libc_getgrent_r_t libc_getgrent_r = NULL;
#endif
static libc_getgrnam_t libc_getgrnam = NULL;
static libc_getgrgid_t libc_getgrgid = NULL;
static libc_setgrent_t libc_setgrent = NULL;
static libc_endgrent_t libc_endgrent = NULL;
static libc_getgrent_t libc_getgrent = NULL;

#ifdef OSF1
static char nss_buf[SIABUFSIZ] = { '\0' };
#else
static char nss_buf[NSS_BUFLEN_GROUP] = { '\0' };
#endif

static int do_ldap_getgrent = 0;

#ifdef OSF1
/* this is the OSF/1 interface, anyway. Disgusting. */
int
getgrent_r (struct group *gr, char *buffer, int len, FILE ** gr_fp)
{
  /* returns 0 or errno */
  NSS_STATUS status;

  if (do_ldap_getgrent == 0)
    {
      INIT_HANDLE ();
      if (libc_getgrent_r == NULL)
	{
	  libc_getgrent_r =
	    (libc_getgrent_r_t) dlsym (_nss_ldap_libc_handle, "getgrent_r");
	}
      if (libc_getgrent_r == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}
      if (libc_getgrent_r (gr, buffer, len, gr_fp) == 0)
	{
	  return 0;
	}
      if (libc_endgrent_r == NULL)
	{
	  libc_endgrent_r =
	    (libc_endgrent_r_t) dlsym (_nss_ldap_libc_handle, "endgrent_r");
	}
      if (libc_endgrent_r == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}
      libc_endgrent_r (gr_fp);
      if (_nss_ldap_setgrent_r () != NSS_SUCCESS)
	{
	  errno = EINVAL;
	  return -1;
	}
      do_ldap_getgrent = 1;
    }

  status = _nss_ldap_getgrent_r (gr, buffer, (size_t) len);
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

struct group *
getgrent (void)
{
  static struct group gr;

  if (do_ldap_getgrent == 0)
    {
      struct group *p;

      INIT_HANDLE ();

      if (libc_getgrent == NULL)
	{
	  libc_getgrent =
	    (libc_getgrent_t) dlsym (_nss_ldap_libc_handle, "getgrent");
	}
      if (libc_getgrent == NULL)
	{
	  return NULL;
	}

      p = libc_getgrent ();
      if (p == NULL)
	{
	  if (libc_endgrent == NULL)
	    {
	      libc_endgrent =
		(libc_endgrent_t) dlsym (_nss_ldap_libc_handle, "endgrent");
	    }
	  if (libc_endgrent == NULL)
	    {
	      return NULL;
	    }
	  libc_endgrent ();
	  if (_nss_ldap_setgrent_r () != NSS_SUCCESS)
	    {
	      return NULL;
	    }
	  do_ldap_getgrent = 1;
	}
      else
	{
	  return p;
	}
    }

  if (_nss_ldap_getgrent_r (&gr, nss_buf, sizeof (nss_buf)) == NSS_SUCCESS)
    return &gr;

  return NULL;
}

#ifdef OSF1
/*
 * XXX we should implement the non-Posix one as well, but I can't be bothered.
 * That doesn't take the last argument, and has a symbol name of getgrgid_r
 * instead of Pgetgrgid_r. Ditto for getgrnam.
 */
int
getgrgid_r (gid_t gid, struct group *grp, char *buffer, size_t len,
	    struct group **result)
{
  NSS_STATUS status;
  INIT_HANDLE ();

  if (libc_getgrgid_r == NULL)
    {
      libc_getgrgid_r =
	(libc_getgrgid_r_t) dlsym (_nss_ldap_libc_handle, "getgrgid_r");
    }
  if (libc_getgrgid_r == NULL)
    {
      return EINVAL;
    }

  if (libc_getgrgid_r (gid, grp, buffer, len, result) == ESUCCESS)
    {
      return ESUCCESS;
    }

  status = _nss_ldap_getgrgid_r (gid, grp, buffer, len);
  switch (status)
    {
    case NSS_TRYAGAIN:
      *result = NULL;
      return ERANGE;
    case NSS_UNAVAIL:
      *result = NULL;
      return ENOENT;
    default:
      *result = grp;
    }
  return ESUCCESS;
}
#endif

struct group *
getgrgid (gid_t gid)
{
  static struct group gr;
  struct group *p;

  INIT_HANDLE ();

  if (libc_getgrgid == NULL)
    {
      libc_getgrgid =
	(libc_getgrgid_t) dlsym (_nss_ldap_libc_handle, "getgrgid");
    }
  if (libc_getgrgid == NULL)
    {
      return NULL;
    }

  p = libc_getgrgid (gid);

  if (p != NULL)
    {
      return p;
    }
  if (_nss_ldap_getgrgid_r (gid, &gr, nss_buf, sizeof (nss_buf)) ==
      NSS_SUCCESS)
    {
      return &gr;
    }
  return NULL;
}

#ifdef OSF1
int
getgrnam_r (const char *name, struct group *grp, char *buffer, size_t len,
	    struct group **result)
{
  NSS_STATUS status;
  INIT_HANDLE ();

  if (libc_getgrnam_r == NULL)
    {
      libc_getgrnam_r =
	(libc_getgrnam_r_t) dlsym (_nss_ldap_libc_handle, "getgrnam_r");
    }
  if (libc_getgrnam_r == NULL)
    {
      return EINVAL;
    }

  if (libc_getgrnam_r (name, grp, buffer, len, result) == ESUCCESS)
    {
      return ESUCCESS;
    }

  status = _nss_ldap_getgrnam_r (name, grp, buffer, len);
  switch (status)
    {
    case NSS_TRYAGAIN:
      *result = NULL;
      return ERANGE;
    case NSS_UNAVAIL:
      *result = NULL;
      return ENOENT;
    default:
      *result = grp;
    }
  return ESUCCESS;
}
#endif

struct group *
getgrnam (const char *name)
{
  static struct group gr;
  struct group *p;

  INIT_HANDLE ();

  if (libc_getgrnam == NULL)
    {
      libc_getgrnam =
	(libc_getgrnam_t) dlsym (_nss_ldap_libc_handle, "getgrnam");
    }
  if (libc_getgrnam == NULL)
    {
      return NULL;
    }

  p = libc_getgrnam (name);

  if (p != NULL)
    {
      return p;
    }

  if (_nss_ldap_getgrnam_r (name, &gr, nss_buf, sizeof (nss_buf)) ==
      NSS_SUCCESS)
    {
      return &gr;
    }

  return NULL;
}

#ifdef OSF1
int
setgrent_r (FILE ** fp)
{
  do_ldap_getgrent = 0;
  INIT_HANDLE ();
  if (libc_setgrent_r == NULL)
    {
      libc_setgrent_r =
	(libc_setgrent_r_t) dlsym (_nss_ldap_libc_handle, "setgrent_r");
    }
  if (libc_setgrent_r != NULL)
    {
      return libc_setgrent_r (fp);
    }
  return EINVAL;
}
#endif

#ifdef OSF1
int
setgrent (void)
#else
void
setgrent (void)
#endif
{
  do_ldap_getgrent = 0;
  INIT_HANDLE ();
  if (libc_setgrent == NULL)
    {
      libc_setgrent =
	(libc_setgrent_t) dlsym (_nss_ldap_libc_handle, "setgrent");
    }
  if (libc_setgrent != NULL)
    {
#ifdef OSF1
      return libc_setgrent ();
#else
      libc_setgrent ();
#endif
    }
}

#ifdef OSF1
void
endgrent_r (FILE ** fp)
{
  if (do_ldap_getgrent == 0)
    {
      INIT_HANDLE ();
      if (libc_endgrent_r == NULL)
	{
	  libc_endgrent_r =
	    (libc_endgrent_r_t) dlsym (_nss_ldap_libc_handle, "endgrent_r");
	}
      if (libc_endgrent_r != NULL)
	{
	  libc_endgrent_r (fp);
	}
    }
  else
    {
      (void) _nss_ldap_endgrent_r ();
    }
}
#endif

void
endgrent (void)
{
  if (do_ldap_getgrent == 0)
    {
      INIT_HANDLE ();
      if (libc_endgrent == NULL)
	{
	  libc_endgrent =
	    (libc_endgrent_t) dlsym (_nss_ldap_libc_handle, "endgrent");
	}
      if (libc_endgrent != NULL)
	{
	  libc_endgrent ();
	}
    }
  else
    {
      (void) _nss_ldap_endgrent_r ();
    }

  do_ldap_getgrent = 0;
}

#endif /* DL_NSS */
