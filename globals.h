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

#ifndef _LDAP_NSS_LDAP_GLOBAL_H
#define _LDAP_NSS_LDAP_GLOBAL_H

#ifdef SUN_NSS
extern mutex_t _nss_ldap_lock;
#elif defined(GNU_NSS)
#include <pthread.h>
extern pthread_mutex_t _nss_ldap_lock;
#endif

extern int _nss_ldap_herrno2nssstat_tab[];
extern int _nss_ldap_herrno2nssstat_tab_count;

extern const char *_nss_ldap_crypt_prefixes_tab[];
extern size_t _nss_ldap_crypt_prefixes_size_tab[];
extern size_t _nss_ldap_crypt_prefixes_tab_count;
extern crypt_prefix_t _nss_ldap_crypt_prefix;

#ifdef DL_NSS
extern void *_nss_ldap_libc_handle;
#endif

#endif /* _LDAP_NSS_LDAP_GLOBAL_H */

