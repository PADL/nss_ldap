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

#ifndef _LDAP_NSS_LDAP_LDAP_RPC_H
#define _LDAP_NSS_LDAP_LDAP_RPC_H

/*
    Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
    and assign any values of "cn" which do NOT match this canonical name
    as aliases.
 */

#define LDAP_CLASS_RPC                  "oncRpc"
#define LDAP_ATTR_RPCNAME               "cn"
#define LDAP_ATTR_RPCNUMBER             "oncRpcNumber"

static const char *rpc_attributes[] =
        { LDAP_ATTR_RPCNAME, LDAP_ATTR_RPCNUMBER, NULL };

static const char filt_getrpcbyname[] =
        "(&(objectclass="LDAP_CLASS_RPC")("LDAP_ATTR_RPCNAME"=%s))";
static const char filt_getrpcbynumber[] =
        "(&(objectclass="LDAP_CLASS_RPC")("LDAP_ATTR_RPCNUMBER"=%d))";
static const char filt_getrpcent[] =
        "(objectclass="LDAP_CLASS_RPC")";

static NSS_STATUS _nss_ldap_parse_rpc(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getrpcbyname_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getrpcbynumber_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_setrpcent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_endrpcent_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getrpcent_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_rpc_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);
#endif /* !GNU_NSS */

#endif /* _LDAP_NSS_LDAP_LDAP_RPC_H */

