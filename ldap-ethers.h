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

#ifdef SUN_NSS
#include <netinet/if_ether.h>
#else
#include <netinet/ether.h>
#endif

#ifndef _LDAP_NSS_LDAP_LDAP_ETHERS_H
#define _LDAP_NSS_LDAP_LDAP_ETHERS_H

#define LDAP_CLASS_HOST                 "ieee802Device"
#define LDAP_ATTR_HOSTNAME              "cn"
#define LDAP_ATTR_ETHERADDR		"macaddress"

static const char *ether_attributes[] =
        { LDAP_ATTR_HOSTNAME, LDAP_ATTR_ETHERADDR, NULL };

static const char filt_gethostton[] = /* opt filter on null macaddress? */
        "(&(objectclass="LDAP_CLASS_HOST")("LDAP_ATTR_HOSTNAME"=%s))";
static const char filt_getntohost[] =
        "(&(objectclass="LDAP_CLASS_HOST")("LDAP_ATTR_ETHERADDR"=%s))";
static const char filt_getetherent[] =
        "(objectclass="LDAP_CLASS_HOST")";

#if defined(TESTING) || defined(DL_NSS)
/* haven't instlled libc.so.6. remove this before release. */
/*
typedef u_char ether_addr_t[6];
struct ether_addr {
        u_char  ether_addr_octet[6];
};
*/
#endif

struct ether
{
	char *e_name;
	struct ether_addr e_addr;
};

/*
typedef u_char ether_addr_t[6];
struct ether_addr {
        u_char  ether_addr_octet[6];
};
 */

static NSS_STATUS _nss_ldap_parse_ether(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen);

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_gethostton_r(nss_backend_t *be, void *fakeargs);
static NSS_STATUS _nss_ldap_getntohost_r(nss_backend_t *be, void *fakeargs);

nss_backend_t *_nss_ldap_ethers_constr(const char *db_name,
        const char *src_name,
        const char *cfg_args);

#elif defined(GNU_NSS)
/* for the record */
NSS_STATUS _nss_ldap_gethostton_r (const char *name, struct ether *eth,
                       char *buffer, size_t buflen, int *errnop);
NSS_STATUS _nss_ldap_getntohost_r (struct ether_addr *addr, struct ether *eth,
                       char *buffer, size_t buflen, int *errnop);
NSS_STATUS _nss_ldap_endetherent (void);
NSS_STATUS _nss_ldap_setetherent (void);
NSS_STATUS _nss_ldap_getetherent_r (struct ether *result, char *buffer, size_t buflen, int *errnop);
#endif


#endif /* _LDAP_NSS_LDAP_LDAP_ETHERS_H */

