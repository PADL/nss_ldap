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

#ifndef _LDAP_NSS_LDAP_LDAP_SPWD_H
#define _LDAP_NSS_LDAP_LDAP_SPWD_H

#define LDAP_CLASS_SHADOW               "shadowAccount"
#define LDAP_ATTR_SHADOW_NAME           "uid"
#define LDAP_ATTR_SHADOW_PASSWD		"userpassword"
#define LDAP_ATTR_SHADOW_LASTCHANGE     "shadowlastchange"
#define LDAP_ATTR_SHADOW_MAX            "shadowmax"
#define LDAP_ATTR_SHADOW_MIN            "shadowmin"
#define LDAP_ATTR_SHADOW_WARN           "shadowwarning"
#define LDAP_ATTR_SHADOW_INACTIVE       "shadowinactive"
#define LDAP_ATTR_SHADOW_EXPIRE         "shadowexpire"
#define LDAP_ATTR_SHADOW_FLAG           "shadowflag"

static const char *sp_attributes[] =
        { LDAP_ATTR_SHADOW_NAME, LDAP_ATTR_SHADOW_PASSWD,
          LDAP_ATTR_SHADOW_LASTCHANGE, LDAP_ATTR_SHADOW_MAX,
          LDAP_ATTR_SHADOW_MIN, LDAP_ATTR_SHADOW_WARN,
          LDAP_ATTR_SHADOW_INACTIVE, LDAP_ATTR_SHADOW_EXPIRE,
	  NULL };

static const char filt_getspnam[] =
        "(&(objectclass="LDAP_CLASS_SHADOW")("LDAP_ATTR_SHADOW_NAME"=%s))";

static const char filt_getspent[] =
        "(objectclass="LDAP_CLASS_SHADOW")";

static NSS_STATUS _nss_ldap_parse_sp(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getspnam_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_setspent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_endspent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getspent_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_shadow_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);
#endif /* !GNU_NSS */

#endif /* _LDAP_NSS_LDAP_LDAP_SPWD_H */

