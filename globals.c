/* Copyright (C) 1997-2003 Luke Howard.
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

#include "config.h"

#ifdef HAVE_THREAD_H
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <lber.h>
#include <ldap.h>
#include <netdb.h>

#include "ldap-nss.h"

static char rcsId[] = "$Id$";

int _nss_ldap_herrno2nssstat_tab[] = {
#ifdef HAVE_NSS_H
  [NSS_SUCCESS - _NSS_LOOKUP_OFFSET] = 0,
  [NSS_TRYAGAIN - _NSS_LOOKUP_OFFSET] = TRY_AGAIN,
  [NSS_NOTFOUND - _NSS_LOOKUP_OFFSET] = HOST_NOT_FOUND,
  [NSS_UNAVAIL - _NSS_LOOKUP_OFFSET] = NO_RECOVERY
#else
#ifdef __GNUC__
  [NSS_SUCCESS] = 0,
  [NSS_TRYAGAIN] = TRY_AGAIN,
  [NSS_NOTFOUND] = HOST_NOT_FOUND,
  [NSS_UNAVAIL] = NO_RECOVERY
#else
  0,
  TRY_AGAIN,
  HOST_NOT_FOUND,
  NO_RECOVERY
#endif				/* __GNUC__ */
#endif
};

size_t _nss_ldap_herrno2nssstat_tab_count =
  (sizeof (_nss_ldap_herrno2nssstat_tab) /
   sizeof (_nss_ldap_herrno2nssstat_tab[0]));

#ifdef HAVE_IRS_H
#ifdef __GNUC__
int _nss_ldap_errno2nssstat_tab[] = {
  [NSS_SUCCESS] = 0,
  [NSS_TRYAGAIN] = ERANGE,
  [NSS_NOTFOUND] = ENOENT,
  [NSS_UNAVAIL] = EPERM
};
#else
int _nss_ldap_errno2nssstat_tab[] = {
  0,
  ERANGE,
  ENOENT,
  EPERM
};
#endif

size_t _nss_ldap_errno2nssstat_tab_count =
  (sizeof (_nss_ldap_errno2nssstat_tab) /
   sizeof (_nss_ldap_errno2nssstat_tab[0]));
#endif /* HAVE_IRS_H */
