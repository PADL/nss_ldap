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

#ifndef _LDAP_NSS_LDAP_LDAP_BP_H
#define _LDAP_NSS_LDAP_LDAP_BP_H

#define LDAP_CLASS_HOST                 "ipHost"
#define LDAP_ATTR_HOSTNAME              "associateddomain"
#define LDAP_ATTR_HOSTADDR              "iphostnumber"
#define LDAP_ATTR_BOOTPARAM		"bootparameter"

/* I'm guessing here. This is certainly wrong. */
struct bootparams
{
	char *bp_name;
	char **bp_params;
};

static char *bp_attributes[] =
        { LDAP_ATTR_HOSTNAME, LDAP_ATTR_HOSTADDR, 
	  LDAP_ATTR_BOOTPARAM, NULL };

static char filt_getbootparamsbyname[] = 
        "(&(objectclass="LDAP_CLASS_HOST")("LDAP_ATTR_HOSTNAME"=%s))";

PARSER _nss_ldap_parse_bp(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

#ifdef SUN_NSS

/*
int parse_bootparams_entry(const char *bp_entry,
    char **bp_uniquehostname, char **bp_sharedhostname,
    char **bp_rootpath, char **bp_swappath, char **bp_dumppath,
    char **bp_execpath, char **bp_kvmpath);
 */

static NSS_STATUS _nss_ldap_getbootparamsbyname_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_bootparams_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);

#endif

#endif /* _LDAP_NSS_LDAP_LDAP_BP_H */

