
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

static char rcsId[] =
"$Id$";

#if !defined(IRS_NSS)		/* no shadow support */

#ifdef IRS_NSS
#include <port_before.h>
#endif

#ifdef SUN_NSS
#include <thread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <lber.h>
#include <ldap.h>

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#include "ldap-nss.h"
#include "ldap-spwd.h"
#include "globals.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_handle_t sp_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_sp (LDAP * ld,
		    LDAPMessage * e,
		    ldap_state_t * pvt,
		    void *result, char *buffer, size_t buflen)
{
  struct spwd *sp = (struct spwd *) result;
  NSS_STATUS stat;
  char *tmp = NULL;

  stat =
    _nss_ldap_assign_passwd (ld, e, AT (userPassword), &sp->sp_pwdp, &buffer,
			     &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (uid), &sp->sp_namp, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowLastChange), &tmp, &buffer,
			      &buflen);
  sp->sp_lstchg = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowMax), &tmp, &buffer, &buflen);
  sp->sp_max = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowMin), &tmp, &buffer, &buflen);
  sp->sp_min = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowWarning), &tmp, &buffer,
			      &buflen);
  sp->sp_warn = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowInactive), &tmp, &buffer,
			      &buflen);
  sp->sp_inact = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowExpire), &tmp, &buffer,
			      &buflen);
  sp->sp_expire = (stat == NSS_SUCCESS) ? atol (tmp) : -1;

  stat =
    _nss_ldap_assign_attrval (ld, e, AT (shadowFlag), &tmp, &buffer, &buflen);
  sp->sp_flag = (stat == NSS_SUCCESS) ? atol (tmp) : 0;

  return NSS_SUCCESS;
}

#ifdef GNU_NSS
NSS_STATUS
_nss_ldap_getspnam_r (const char *name,
		      struct spwd * result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, filt_getspnam,
	       sp_attributes, _nss_ldap_parse_sp);
}
#elif defined(SUN_NSS)
static NSS_STATUS
_nss_ldap_getspnam_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, filt_getspnam, sp_attributes, _nss_ldap_parse_sp);
}
#endif /* GNU_NSS */

#if defined(GNU_NSS)
NSS_STATUS 
_nss_ldap_setspent (void)
#else
static NSS_STATUS
_nss_ldap_setspent_r (nss_backend_t * sp_context, void *args)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_SETENT (sp_context);
}
#endif

#if defined(GNU_NSS)
NSS_STATUS 
_nss_ldap_endspent (void)
#else
static NSS_STATUS
_nss_ldap_endspent_r (nss_backend_t * sp_context, void *args)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_ENDENT (sp_context);
}
#endif

#ifdef GNU_NSS
NSS_STATUS
_nss_ldap_getspent_r (struct spwd *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (sp_context, result, buffer, buflen, errnop, filt_getspent,
		 sp_attributes, _nss_ldap_parse_sp);
}
#elif defined(SUN_NSS)
static NSS_STATUS
_nss_ldap_getspent_r (nss_backend_t * sp_context, void *args)
{
  LOOKUP_GETENT (args, sp_context, filt_getspent, sp_attributes,
		 _nss_ldap_parse_sp);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_shadow_destr (nss_backend_t * sp_context, void *args)
{
  return _nss_ldap_default_destr (sp_context, args);
}

static nss_backend_op_t shadow_ops[] =
{
  _nss_ldap_shadow_destr,
  _nss_ldap_endspent_r,		/* NSS_DBOP_ENDENT */
  _nss_ldap_setspent_r,		/* NSS_DBOP_SETENT */
  _nss_ldap_getspent_r,		/* NSS_DBOP_GETENT */
  _nss_ldap_getspnam_r		/* NSS_DBOP_SHADOW_BYNAME */
};


nss_backend_t *
_nss_ldap_shadow_constr (const char *db_name,
			 const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = shadow_ops;
  be->n_ops = sizeof (shadow_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !GNU_NSS */
#endif /* !IRS_NSS */
