
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

#ifndef _LDAP_NSS_LDAP_LDAP_NETWORK_H
#define _LDAP_NSS_LDAP_LDAP_NETWORK_H


#define LDAP_CLASS_NETWORK              "ipNetwork"
#define LDAP_ATTR_NETWORKNAME           "cn"
#define LDAP_ATTR_NETWORKADDR           "ipnetworknumber"
#define LDAP_ATTR_NETWORKMASK           "ipnetmasknumber"

static NSS_STATUS _nss_ldap_parse_net(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

static const char *net_attributes[] =
        { LDAP_ATTR_NETWORKNAME, LDAP_ATTR_NETWORKADDR, 
          NULL };

static const char filt_getnetbyname[] =
        "(&(objectclass="LDAP_CLASS_NETWORK")("LDAP_ATTR_NETWORKNAME"=%s))";
static const char filt_getnetbyaddr[] =
        "(&(objectclass="LDAP_CLASS_NETWORK")("LDAP_ATTR_NETWORKADDR"=%s))";
static const char filt_getnetent[] =
        "(objectclass="LDAP_CLASS_NETWORK")";


#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getnetbyname_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getnetbyaddr_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_setnetent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_endnetent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getnetent_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_networks_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);

#endif /* !GNU_NSS */

#endif /* _LDAP_NSS_LDAP_LDAP_NETWORK_H */

