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

   $Id$
 */

#ifndef _LDAP_NSS_LDAP_LDAP_NETGRP_H
#define _LDAP_NSS_LDAP_LDAP_NETGRP_H

#define LDAP_CLASS_NETGROUP             "nisNetgroup"
#define LDAP_ATTR_NETGROUPNAME          "cn"
#define LDAP_ATTR_NETGROUPTRIPLE	"nisnetgrouptriple"
#define LDAP_ATTR_NETGROUPMEMBER        "membernisnetgroup"

/*
     int getnetgrent_r(char **machinep, char **userp,
          char **domainp, char *buffer, int buflen);

     int setnetgrent(const char *netgroup);

     int endnetgrent(void);
 */

static char *netgr_attributes[] =
        { LDAP_ATTR_NETGROUPNAME, LDAP_ATTR_NETGROUPTRIPLE, LDAP_ATTR_NETGROUPMEMBER, NULL };

static char *filt_setnetgrent[] = 
	"(&(objectclass="LDAP_CLASS_NETGROUP")("LDAP_ATTR_NETGROUPNAME"=%s))";

PARSER _nss_ldap_parse_netgr(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_setnetgrent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_endnetgrent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getnetgrent_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_netgroup_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);
#endif /* !GNU_NSS */

#endif /* _LDAP_NSS_LDAP_LDAP_NETGRP_H */

