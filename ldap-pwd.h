
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

#ifndef _LDAP_NSS_LDAP_LDAP_PWD_H
#define _LDAP_NSS_LDAP_LDAP_PWD_H

static const char *pw_attributes[] =
{AT (uid), AT (userPassword),
 AT (uidNumber), AT (gidNumber),
 AT (cn), AT (homeDirectory),
 AT (loginShell), AT (gecos),
 AT (description), NULL};

static const char filt_getpwnam[] =
#ifdef IDS_UID
"(&(objectclass=" 
OC (posixAccount) ")(|(" AT (uid) "=%s)(" AT (uid) "=%s@*)))";
#else
"(&(objectclass=" OC (posixAccount) ")(" AT (uid) "=%s))";
#endif
     static const char filt_getpwuid[] =
     "(&(objectclass=" OC (posixAccount) ")(" AT (uidNumber) "=%d))";
     static const char filt_getpwent[] =
     "(objectclass=" OC (posixAccount) ")";

     static NSS_STATUS _nss_ldap_parse_pw (
					    LDAP * ld,
					    LDAPMessage * e,
					    ldap_state_t * pvt,
					    void *result,
					    char *buffer,
					    size_t buflen);

#ifdef SUN_NSS
     static NSS_STATUS _nss_ldap_getpwnam_r (nss_backend_t * be, void *fakeargs);
     static NSS_STATUS _nss_ldap_getpwuid_r (nss_backend_t * be, void *fakeargs);
     static NSS_STATUS _nss_ldap_setpwent_r (nss_backend_t * be, void *fakeargs);
     static NSS_STATUS _nss_ldap_endpwent_r (nss_backend_t * be, void *fakeargs);
     static NSS_STATUS _nss_ldap_getpwent_r (nss_backend_t * be, void *fakeargs);

     nss_backend_t *_nss_ldap_passwd_constr (const char *db_name,
					     const char *src_name,
					     const char *cfg_args);
#endif

#endif /* _LDAP_NSS_LDAP_LDAP_PWD_H */
