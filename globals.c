
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
 */

#ifdef SUN_NSS
#include <thread.h>
#elif defined(GNU_NSS)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <lber.h>
#include <ldap.h>

#include <netdb.h>

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#include "ldap-nss.h"

static char rcsId[] = "$Id$";

#ifdef SUN_NSS
mutex_t _nss_ldap_lock = DEFAULTMUTEX;
#else
pthread_mutex_t _nss_ldap_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifdef DL_NSS
void *_nss_ldap_libc_handle = NULL;
#endif

int _nss_ldap_herrno2nssstat_tab[] =
{
#ifdef GNU_NSS
  [NSS_SUCCESS - _NSS_LOOKUP_OFFSET] = 0,
  [NSS_TRYAGAIN - _NSS_LOOKUP_OFFSET] = TRY_AGAIN,
  [NSS_NOTFOUND - _NSS_LOOKUP_OFFSET] = HOST_NOT_FOUND,
  [NSS_UNAVAIL - _NSS_LOOKUP_OFFSET] = NO_RECOVERY
#elif !defined(__GNUC__) || defined(NeXT)
  0,
  HOST_NOT_FOUND,
  NO_RECOVERY,
  TRY_AGAIN
#else
  [NSS_SUCCESS] = 0,
  [NSS_TRYAGAIN] = TRY_AGAIN,
  [NSS_NOTFOUND] = HOST_NOT_FOUND,
  [NSS_UNAVAIL] = NO_RECOVERY
#endif
};

size_t _nss_ldap_herrno2nssstat_tab_count = (sizeof (_nss_ldap_herrno2nssstat_tab) / sizeof (_nss_ldap_herrno2nssstat_tab[0]));

const char *_nss_ldap_crypt_prefixes_tab[] =
{
#if !defined(__GNUC__) || defined(NeXT)
  "{CRYPT}",
  "{MD5}",
  "{SHA}"
#else
  [UNIX_CRYPT] = "{CRYPT}",
  [MD5_CRYPT] = "{MD5}",
  [SHA_CRYPT] = "{SHA}"
#endif
};

size_t _nss_ldap_crypt_prefixes_size_tab[] =
{
#if !defined(__GNUC__) || defined(NeXT)
  sizeof ("{CRYPT}") - 1,
  sizeof ("{MD5}") - 1,
  sizeof ("{SHA}") - 1
#else
  [UNIX_CRYPT] = sizeof ("{CRYPT}") - 1,
  [MD5_CRYPT] = sizeof ("{MD5}") - 1,
  [SHA_CRYPT] = sizeof ("{SHA}") - 1
#endif
};

crypt_prefix_t _nss_ldap_crypt_prefix = UNIX_CRYPT;

size_t _nss_ldap_crypt_prefixes_tab_count = (sizeof (_nss_ldap_crypt_prefixes_tab) / sizeof (_nss_ldap_crypt_prefixes_tab[0]));
