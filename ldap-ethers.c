
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

   $Id$
 */


static char rcsId[] = "$Id$";

#if !defined(IRS_NSS)

#ifdef IRS_NSS
#include <port_before.h>
#endif

#ifdef SUN_NSS
#include <thread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <lber.h>
#include <ldap.h>

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef SUN_NSS
#include <netinet/if_ether.h>
#endif

#include "ldap-nss.h"
#include "ldap-ethers.h"
#include "util.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_handle_t ether_context = NULL;
#endif

#ifdef SUN_NSS
extern struct ether_addr *ether_aton (char *s);
extern char *ether_ntoa (struct ether_addr *e);
#endif

static NSS_STATUS
_nss_ldap_parse_ether (
			LDAP * ld,
			LDAPMessage * e,
			ldap_state_t * pvt,
			void *result,
			char *buffer,
			size_t buflen)
{
  struct ether *ether = (struct ether *) result;
  char *saddr;
  NSS_STATUS stat;
  struct ether_addr *addr;

  stat = _nss_ldap_assign_attrval (ld, e, LDAP_ATTR_HOSTNAME,
				   &ether->e_name, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat = _nss_ldap_assign_attrval (ld, e, LDAP_ATTR_ETHERADDR, &saddr,
				   &buffer, &buflen);

  if (stat != NSS_SUCCESS || ((addr = ether_aton (saddr)) == NULL))
    return NSS_NOTFOUND;

  memcpy (&ether->e_addr, addr, sizeof (*addr));

  return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_gethostton_r (nss_backend_t * be, void *args)
{
  struct ether result;
  ldap_args_t a;
  char buffer[NSS_BUFLEN_ETHERS];
  NSS_STATUS status;

  LA_INIT (a);
  LA_STRING (a) = NSS_ARGS (args)->key.name;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				&result,
				buffer,
				sizeof (buffer),
				&NSS_ARGS (args)->erange,
				filt_gethostton,
				(const char **) ether_attributes,
				_nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.result, &result.e_addr, sizeof (result.e_addr));
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
    }

  return status;
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_gethostton_r (const char *name, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, filt_gethostton, ether_attributes, _nss_ldap_parse_ether);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_getntohost_r (nss_backend_t * be, void *args)
{
  struct ether result;
  char *addr;
  ldap_args_t a;
  char buffer[NSS_BUFLEN_ETHERS];
  NSS_STATUS status;

  addr = ether_ntoa ((struct ether_addr *) (NSS_ARGS (args)->key.ether));

  LA_INIT (a);
  LA_STRING (a) = addr;
  LA_TYPE (a) = LA_TYPE_STRING;

  status = _nss_ldap_getbyname (&a,
				&result,
				buffer,
				sizeof (buffer),
				&NSS_ARGS (args)->erange,
				filt_getntohost,
				(const char **) ether_attributes,
				_nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.result, &result.e_addr, sizeof (result.e_addr));
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
    }
  else
    {
      NSS_ARGS (args)->returnval = NULL;
    }

  return status;
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_getntohost_r (struct ether_addr * addr, struct ether * result,
			char *buffer, size_t buflen, int *errnop)
{
/* The correct ether_ntoa call would have a struct ether instead of whatever
   result->e_addr is */

  LOOKUP_NAME (ether_ntoa ((struct ether_addr *) (&result->e_addr)), result, buffer, buflen, errnop, filt_getntohost, ether_attributes, _nss_ldap_parse_ether);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_setetherent_r (nss_backend_t * ether_context, void *fakeargs)
#elif defined(GNU_NSS)
     NSS_STATUS _nss_ldap_setetherent (void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_SETENT (ether_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_endetherent_r (nss_backend_t * ether_context, void *fakeargs)
#elif defined(GNU_NSS)
     NSS_STATUS _nss_ldap_endetherent (void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_ENDENT (ether_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_getetherent_r (nss_backend_t * ether_context, void *args)
{
  struct ether result;
  NSS_STATUS status;

  status = _nss_ldap_getent (
			      ((nss_ldap_backend_t *) ether_context)->state,
			      &result,
			      NSS_ARGS (args)->buf.buffer,
			      NSS_ARGS (args)->buf.buflen,
			      &NSS_ARGS (args)->erange,
			      filt_getetherent,
			      (const char **) ether_attributes,
			      _nss_ldap_parse_ether);

  if (status == NSS_SUCCESS)
    {
      memcpy (NSS_ARGS (args)->buf.result, &result.e_addr, sizeof (result.e_addr));
      NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;
    }
  else
    {
      NSS_ARGS (args)->returnval = NULL;
    }

  return status;
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_getetherent_r (struct ether * result, char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (ether_context, result, buffer, buflen, errnop, filt_getetherent, ether_attributes, _nss_ldap_parse_ether);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_ethers_destr (nss_backend_t * ether_context, void *args)
{
  return _nss_ldap_default_destr (ether_context, args);
}

static nss_backend_op_t ethers_ops[] =
{
  _nss_ldap_ethers_destr,
  _nss_ldap_gethostton_r,
  _nss_ldap_getntohost_r
};

nss_backend_t *
_nss_ldap_ethers_constr (const char *db_name,
			 const char *src_name,
			 const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = ethers_ops;
  be->n_ops = sizeof (ethers_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;

}

#endif /* !GNU_NSS */

#endif /* !IRS_NSS */
