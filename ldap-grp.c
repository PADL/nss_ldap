/* Copyright (C) 1997 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@xedoc.com>, 1997.

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

static char rcsId[] = "$Id$";

#ifdef IRS_NSS
#include <port_before.h>
#endif

#ifdef SUN_NSS
#include <thread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <grp.h>
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
#include "ldap-grp.h"
#include "globals.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_key_t gr_context = NULL;
#elif defined(SUN_NSS)
static context_key_t gr_context = { 0 };
#endif

PARSER _nss_ldap_parse_gr(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen)
{
	struct group *gr = (struct group *)result;
	char *gid;
	NSS_STATUS stat;

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_GROUP_GID, &gid, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	gr->gr_gid = (*gid == '\0') ? GID_NOBODY : (gid_t) atol(gid);

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_GROUPNAME, &gr->gr_name, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	stat = _nss_ldap_assign_passwd(ld, e, LDAP_ATTR_GPASSWD, &gr->gr_passwd, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	stat = _nss_ldap_assign_attrvals(ld, e, LDAP_ATTR_USERS, NULL, &gr->gr_mem, &buffer, &buflen, NULL);
	if (stat != NSS_SUCCESS) return stat;

	return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getgroupsbymember_r(nss_backend_t *be, void *args)
{
	/* filt_getgroupsbymember */

	return NSS_NOTFOUND;
}
#endif /* SUN_NSS */

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getgrnam_r(
	const char *name,
	struct group *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_NAME(name, result, buffer, buflen, filt_getgrnam, gr_attributes, _nss_ldap_parse_gr);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getgrnam_r(nss_backend_t *be, void *args)
{
	LOOKUP_NAME(args, filt_getgrnam, gr_attributes, _nss_ldap_parse_gr);
}
#endif

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getgrgid_r(
	gid_t gid,
	struct group *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_NUMBER(gid, result, buffer, buflen, filt_getgrgid, gr_attributes, _nss_ldap_parse_gr);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getgrgid_r(nss_backend_t *be, void *args)
{
	LOOKUP_NUMBER(args, key.gid, filt_getgrgid, gr_attributes, _nss_ldap_parse_gr);
}
#endif

#if defined(GNU_NSS) 
NSS_STATUS _nss_ldap_setgrent_r(void)
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_setgrent_r(nss_backend_t *be, void *args)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_SETENT(gr_context);
}
#endif

#if defined(GNU_NSS) 
NSS_STATUS _nss_ldap_endgrent_r(void)
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_endgrent_r(nss_backend_t *be, void *args)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_ENDENT(gr_context);
}
#endif

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getgrent_r(
	struct group *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_GETENT(gr_context, result, buffer, buflen, filt_getgrent, gr_attributes, _nss_ldap_parse_gr);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getgrent_r(nss_backend_t *be,
	void *args)
{
	LOOKUP_GETENT(args, gr_context, filt_getgrent, gr_attributes, _nss_ldap_parse_gr);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_group_destr(nss_backend_t *be, void *args)
{
	_nss_ldap_default_destr(&gr_context);
	return NSS_SUCCESS;
}

static nss_backend_op_t group_ops[] =
{
	_nss_ldap_group_destr,
	_nss_ldap_endgrent_r,
	_nss_ldap_setgrent_r,
	_nss_ldap_getgrent_r,
	_nss_ldap_getgrnam_r,
	_nss_ldap_getgrgid_r
/*	_nss_ldap_getgroupsbymember_r	*/
};

nss_backend_t *_nss_ldap_group_constr(const char *db_name,
	const char *src_name,
	const char *cfg_args)
{
	static nss_backend_t be;

	debug("_nss_ldap_group_constr");

	be.ops = group_ops;
	be.n_ops = sizeof(group_ops) / sizeof(nss_backend_op_t);

	if (_nss_ldap_default_constr(&gr_context) != NSS_SUCCESS)
		return NULL;

	return &be;
}

#endif /* !GNU_NSS */

#ifdef IRS_NSS
#include "irs-grp.c"
#endif

