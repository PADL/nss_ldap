
/* Copyright (C) 1997 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1997.
   (The author maintains a non-exclusive licence to distribute this file
   under their own conditions.)

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

#ifndef _LDAP_NSS_LDAP_UTIL_H
#define _LDAP_NSS_LDAP_UTIL_H

/* utility routines.  */

#define CN_ATTR			"CN"

#define DC_ATTR			"DC"
#define DC_ATTR_AVA		DC_ATTR"="
#define DC_ATTR_AVA_LEN		(sizeof(DC_ATTR_AVA) - 1)

/*
 * get the RDN's value: eg. if the RDN was cn=lukeh, getrdnvalue(entry)
 * would return lukeh.
 */
NSS_STATUS _nss_ldap_getrdnvalue (
				   LDAP * ld,
				   LDAPMessage * entry,
				   const char *rdntype,
				   char **rval,
				   char **buf,
				   size_t * len);

#ifdef RFC2307BIS
/*
 * map a distinguished name to a login naem.
 */
NSS_STATUS _nss_ldap_dn2uid (
			      LDAP * ld,
			      const char *dn,
			      char **uid,
			      char **buf,
			      size_t * len);
#endif /* RFC2307BIS */

#define NSS_LDAP_CONFIG_BUFSIZ	1024
#define NSS_LDAP_KEY_HOST	"host"
#define NSS_LDAP_KEY_SCOPE	"scope"
#define NSS_LDAP_KEY_BASE	"base"
#define NSS_LDAP_KEY_PORT	"port"
#define NSS_LDAP_KEY_BINDDN	"binddn"
#define NSS_LDAP_KEY_BINDPW     "bindpw"
#define NSS_LDAP_KEY_ROOTBINDDN	"rootbinddn"
#define NSS_LDAP_KEY_LDAP_VERSION	"ldap_version"
#define NSS_LDAP_KEY_SSL	"ssl"
#define NSS_LDAP_KEY_SSLPATH	"sslpath"
#define NSS_LDAP_PATH_CONF	"/etc/ldap.conf"
#define NSS_LDAP_PATH_ROOTPASSWD	"/etc/ldap.secret"

/*
 * There are a number of means of obtaining configuration information.
 *
 * (a) DHCP (Cf draft-hedstrom-dhc-ldap-00.txt)
 * (b) a configuration file (/etc/ldap.conf) **
 * (c) a coldstart file & subsequent referrals from the LDAP server
 * (d) a custom LDAP bind protocol
 * (e) DNS **
 *
 * This should be opaque to the rest of the library.
 * ** implemented
 */

NSS_STATUS _nss_ldap_readconfig (
				  ldap_config_t ** result,
				  char *buf,
				  size_t buflen
);

#define MAP_H_ERRNO(nss_status, herr)   do { \
	if ((unsigned int) (nss_status - _NSS_LOOKUP_OFFSET) > _nss_ldap_herrno2nssstat_tab_count) \
		herr = NO_RECOVERY; \
	herr = _nss_ldap_herrno2nssstat_tab[nss_status - _NSS_LOOKUP_OFFSET]; \
	} while (0)

#endif /* _LDAP_NSS_LDAP_UTIL_H */
