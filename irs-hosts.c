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

#ifdef IRS_NSS

#include <errno.h>
#include "irs-nss.h"

/* $Id$ */


static void ho_close (struct irs_ho *this);
static struct hostent *ho_byname (struct irs_ho *this, const char *name);
static struct hostent *ho_byname2 (struct irs_ho *this, const char *name,
				   int af);
static struct hostent *ho_byaddr (struct irs_ho *this, const void *addr,
				  int len, int af);
static struct hostent *ho_next (struct irs_ho *this);
static void ho_rewind (struct irs_ho *this);
static void ho_minimize (struct irs_ho *this);


static const u_char mapped[] =
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
static const u_char tunnelled[] =
{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

struct pvt
  {
    struct hostent result;
    char buffer[NSS_BUFLEN_HOSTS];
    context_handle_t state;
  };

static struct hostent *
ho_byname (struct irs_ho *this, const char *name)
{
  NSS_STATUS s;
  struct pvt *pvt = (struct pvt *) this->private;
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = LA_TYPE_STRING;

  s = _nss_ldap_getbyname (&a,
			   &pvt->result,
			   pvt->buffer,
			   sizeof (pvt->buffer),
			   filt_gethostbyname,
			   (const char **) host_attributes,
			   _nss_ldap_parse_host);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

static struct hostent *
ho_byaddr (struct irs_ho *this, const void *addr, int len, int af)
{
  struct pvt *pvt = (struct pvt *) this->private;
  char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
  const u_char *uaddr = addr;
  NSS_STATUS s;
  ldap_args_t a;

  if (af == AF_INET6 && len == IN6ADDRSZ
      && (!memcmp (uaddr, mapped, sizeof mapped) ||
	  !memcmp (uaddr, tunnelled, sizeof tunnelled)))
    {
      /* Unmap. */
      addr = (u_char *) addr + sizeof mapped;
      uaddr += sizeof mapped;
      af = AF_INET;
      len = INADDRSZ;
    }
  if (inet_ntop (af, uaddr, tmp, sizeof tmp) == NULL)
    {
      h_errno = NETDB_INTERNAL;
      return (NULL);
    }

  LA_INIT (a);
  LA_STRING (a) = tmp;
  LA_TYPE (a) = LA_TYPE_STRING;

  s = _nss_ldap_getbyname (&a,
			   &pvt->result,
			   pvt->buffer,
			   sizeof (pvt->buffer),
			   filt_gethostbyaddr,
			   (const char **) host_attributes,
			   _nss_ldap_parse_host);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

static void
ho_close (struct irs_ho *this)
{
  LOOKUP_ENDENT (this);
}

static struct hostent *
ho_next (struct irs_ho *this)
{
  struct pvt *pvt = (struct pvt *) this->private;
  NSS_STATUS s;

  s = _nss_ldap_getent (pvt->state,
			&pvt->result,
			pvt->buffer,
			sizeof (pvt->buffer),
			filt_gethostent,
			(const char **) host_attributes,
			_nss_ldap_parse_host);

  if (s != NSS_SUCCESS)
    {
      MAP_H_ERRNO (s, h_errno);
      return NULL;
    }
  return &pvt->result;
}

static void
ho_rewind (struct irs_ho *this)
{
  LOOKUP_SETENT (this);
}

static void
ho_minimize (struct irs_ho *this)
{
}

struct irs_ho *
irs_ldap_ho (struct irs_acc *this)
{
  struct irs_ho *ho;
  struct pvt *pvt;

  ho = calloc (1, sizeof (*ho));
  if (ho == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    return NULL;

  pvt->state = NULL;
  ho->private = pvt;
  ho->close = ho_close;
  ho->next = ho_next;
  ho->byname = ho_byname;
/*      ho->byname2 = ho_byname2; */
  ho->byaddr = ho_byaddr;
  ho->rewind = ho_rewind;
  ho->minimize = ho_minimize;
  return ho;
}

#endif /*IRS_NSS */
