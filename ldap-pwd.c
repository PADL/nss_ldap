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
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <pwd.h>
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
#include "ldap-pwd.h"
#include "globals.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_handle_t pw_context = NULL;
#endif

static INLINE NSS_STATUS _nss_ldap_assign_emptystring(
        char **valptr,
        char **buffer,
        size_t *buflen);

static INLINE NSS_STATUS _nss_ldap_assign_emptystring(
        char **valptr,
        char **buffer,
        size_t *buflen)
{
	if (*buflen < 2)
		return NSS_TRYAGAIN;

	*valptr = *buffer;

	**valptr = '\0';

	(*buffer)++;
	(*buflen)--;

	return NSS_SUCCESS;
}


static NSS_STATUS _nss_ldap_parse_pw(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen)
{
	struct passwd *pw = (struct passwd *)result;
	char *uid, *gid;
	NSS_STATUS stat;
	char tmpbuf[sizeof "-4294967295"];
	size_t tmplen;
	char *tmp;

#ifdef IDS_UID
	/* ids-dirnaming drafts endorses uid values like
	 * uid=lukeh@xedoc.com,dc=xedoc,dc=com. This is bogus IMHO, but...
	 */
	char *at;
#endif

	stat = _nss_ldap_assign_passwd(ld, e, LDAP_ATTR_PASSWD, &pw->pw_passwd, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		return stat;

#ifdef IDS_UID
	if ((at = strchr(pw->pw_passwd, '@')) != NULL)
		*at = '\0';
#endif

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_USERNAME, &pw->pw_name, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		return stat;

	tmp = tmpbuf;
	tmplen = sizeof(tmpbuf);
	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_UID, &uid, &tmp, &tmplen);
	if (stat != NSS_SUCCESS)
		return stat;
	pw->pw_uid = (*uid == '\0') ? UID_NOBODY : (uid_t) atol(uid);

	tmp = tmpbuf;
	tmplen = sizeof(tmpbuf);
	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_USER_GID, &gid, &tmp, &tmplen);
	if (stat != NSS_SUCCESS)
		return stat;
	pw->pw_gid = (*gid == '\0') ? GID_NOBODY : (gid_t) atol(gid);

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_GECOS, &pw->pw_gecos, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		{
		pw->pw_gecos = NULL;
		stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_REALNAME, &pw->pw_gecos, &buffer, &buflen);
		if (stat != NSS_SUCCESS)
			return stat;
		}

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_HOME, &pw->pw_dir, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		return stat;

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_SHELL, &pw->pw_shell, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		(void) _nss_ldap_assign_emptystring(&pw->pw_shell, &buffer, &buflen);

#ifdef SUN_NSS
	/* Is this field in POSIX, or even used? */
	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_COMMENT, &pw->pw_comment, &buffer, &buflen);
	if (stat != NSS_SUCCESS)
		(void) _nss_ldap_assign_emptystring(&pw->pw_comment, &buffer, &buflen);

	(void) _nss_ldap_assign_emptystring(&pw->pw_age, &buffer, &buflen);
#endif

	return NSS_SUCCESS;
}

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getpwnam_r(
	const char *name,
	struct passwd *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_NAME(name, result, buffer, buflen, filt_getpwnam, pw_attributes, _nss_ldap_parse_pw);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getpwnam_r(nss_backend_t *be, void *args)
{
	LOOKUP_NAME(args, filt_getpwnam, pw_attributes, _nss_ldap_parse_pw);
}
#endif /* GNU_NSS */

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getpwuid_r(
	uid_t uid,
	struct passwd *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_NUMBER(uid, result, buffer, buflen, filt_getpwuid, pw_attributes, _nss_ldap_parse_pw);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getpwuid_r(nss_backend_t *be, void *args)
{
	LOOKUP_NUMBER(args, key.uid, filt_getpwuid, pw_attributes, _nss_ldap_parse_pw);
}
#endif

#if defined(GNU_NSS) 
NSS_STATUS _nss_ldap_setpwent(void)
{
	LOOKUP_SETENT(pw_context);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_setpwent_r(nss_backend_t *be, void *args)
{
	LOOKUP_SETENT(be);
}
#endif

#if defined(GNU_NSS) 
NSS_STATUS _nss_ldap_endpwent(void)
{
	LOOKUP_ENDENT(pw_context);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_endpwent_r(nss_backend_t *be, void *args)
{
	LOOKUP_ENDENT(be);
}
#endif

#ifdef GNU_NSS
NSS_STATUS _nss_ldap_getpwent_r(
	struct passwd *result,
	char *buffer,
	size_t buflen)
{
	LOOKUP_GETENT(pw_context, result, buffer, buflen, filt_getpwent, pw_attributes, _nss_ldap_parse_pw);
}
#elif defined(SUN_NSS)
static NSS_STATUS _nss_ldap_getpwent_r(nss_backend_t *be, void *args)
{
	LOOKUP_GETENT(args, be, filt_getpwent, pw_attributes, _nss_ldap_parse_pw);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_passwd_destr(nss_backend_t *pw_context, void *args)
{
	return _nss_ldap_default_destr(pw_context, args);
}

static nss_backend_op_t passwd_ops[] =
{
	_nss_ldap_passwd_destr,
	_nss_ldap_endpwent_r,	/* NSS_DBOP_ENDENT */
	_nss_ldap_setpwent_r,	/* NSS_DBOP_SETENT */
	_nss_ldap_getpwent_r,	/* NSS_DBOP_GETENT */
	_nss_ldap_getpwnam_r,	/* NSS_DBOP_PASSWD_BYNAME */
	_nss_ldap_getpwuid_r	/* NSS_DBOP_PASSWD_BYUID */
};

nss_backend_t *_nss_ldap_passwd_constr(const char *db_name,
	const char *src_name,
	const char *cfg_args)
{
	nss_ldap_backend_t *be;

	if (!(be = (nss_ldap_backend_t *)malloc(sizeof(*be))))
		return NULL;

	be->ops = passwd_ops;
	be->n_ops = sizeof(passwd_ops) / sizeof(nss_backend_op_t);

	if (_nss_ldap_default_constr(be) != NSS_SUCCESS)
		return NULL;

	return (nss_backend_t *)be;
}


#endif /* !GNU_NSS */

#ifdef IRS_NSS
#include "irs-pwd.c"
#endif

