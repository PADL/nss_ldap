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

#ifndef _LDAP_NSS_LDAP_IRS_H
#define _LDAP_NSS_LDAP_IRS_H

#ifdef IRS_NSS

#include <irs_p.h>

extern struct irs_gr *  irs_ldap_gr __P((struct irs_acc *));
extern struct irs_pw *  irs_ldap_pw __P((struct irs_acc *));
extern struct irs_sv *  irs_ldap_sv __P((struct irs_acc *));
extern struct irs_pr *  irs_ldap_pr __P((struct irs_acc *));
extern struct irs_ho *  irs_ldap_ho __P((struct irs_acc *));
extern struct irs_nw *  irs_ldap_nw __P((struct irs_acc *));
extern struct irs_ng *  irs_ldap_ng __P((struct irs_acc *));

#endif

#ifndef SUN_NSS

#define NSS_BUFSIZ              1024

#define NSS_LINELEN_ETHERS      NSS_BUFSIZ
#define NSS_LINELEN_GROUP       NSS_BUFSIZ
#define NSS_LINELEN_HOSTS       NSS_BUFSIZ
#define NSS_LINELEN_NETMASKS    NSS_BUFSIZ
#define NSS_LINELEN_NETWORKS    NSS_BUFSIZ
#define NSS_LINELEN_PASSWD      NSS_BUFSIZ
#define NSS_LINELEN_PROTOCOLS   NSS_BUFSIZ
#define NSS_LINELEN_RPC         NSS_BUFSIZ
#define NSS_LINELEN_SERVICES    NSS_BUFSIZ
#define NSS_LINELEN_SHADOW      NSS_BUFSIZ
#define NSS_LINELEN_BOOTPARAMS  NSS_BUFSIZ

/*
 * Reasonable defaults for 'buflen' values passed to _r functions.  The BSD
 * and SunOS 4.x implementations of the getXXXbyYYY() functions used hard-
 * coded array sizes;  the values here are meant to handle anything that
 * those implementations handled.
 * === These might more reasonably go in <pwd.h>, <netdb.h> et al
 */

#define NSS_BUFLEN_GROUP        (NSS_LINELEN_GROUP + 200 * sizeof (char *))
#define NSS_BUFLEN_HOSTS        \
        (NSS_LINELEN_HOSTS + (MAXALIASES + MAXALIASES + 2) * sizeof (char *))
#define NSS_BUFLEN_NETGROUP     (MAXHOSTNAMELEN * 2 + LOGNAME_MAX + 3)
#define NSS_BUFLEN_NETWORKS     NSS_LINELEN_NETWORKS    /* === ?  + 35 * 4 */
#define NSS_BUFLEN_PASSWD       NSS_LINELEN_PASSWD
#define NSS_BUFLEN_PROTOCOLS    NSS_LINELEN_PROTOCOLS   /* === ?  + 35 * 4 */
#define NSS_BUFLEN_RPC          NSS_LINELEN_RPC         /* === ?  + 35 * 4 */
#define NSS_BUFLEN_SERVICES     NSS_LINELEN_SERVICES    /* === ?  + 35 * 4 */
#define NSS_BUFLEN_SHADOW       NSS_LINELEN_SHADOW
#define NSS_BUFLEN_ETHERS       NSS_LINELEN_ETHERS
#define NSS_BUFLEN_BOOTPARAMS   NSS_LINELEN_BOOTPARAMS
#endif

#endif /* _LDAP_NSS_LDAP_IRS_H */

