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

   $Id$
 */

#ifndef _LDAP_NSS_LDAP_IRS_H
#define _LDAP_NSS_LDAP_IRS_H

#ifdef HAVE_IRS_H
/*
 * This header is only needed when using the BSD Information 
 * Retrieval Service. It is not necessary for the Solaris or
 * GNU nameservice switch modules.
 */
#include <irs.h>
#endif

struct irs_gr *irs_ldap_gr __P ((struct irs_acc *));
struct irs_pw *irs_ldap_pw __P ((struct irs_acc *));
struct irs_sv *irs_ldap_sv __P ((struct irs_acc *));
struct irs_pr *irs_ldap_pr __P ((struct irs_acc *));
struct irs_ho *irs_ldap_ho __P ((struct irs_acc *));
struct irs_nw *irs_ldap_nw __P ((struct irs_acc *));
/* not done yet */
struct irs_ng *irs_ldap_ng __P ((struct irs_acc *));

/* Keep namespace clean. */
#define irs_ldap_acc	__irs_ldap_acc

struct irs_acc *irs_ldap_acc __P ((const char *));

#define make_group_list __make_group_list

extern int make_group_list (struct irs_gr *, const char *,
			    gid_t, gid_t *, int *);

#ifdef AIX
#define IRS_EXPORT
#else
#define IRS_EXPORT static
#endif

/*
 * These lengths were derived from the Solaris headers.
 * Copyright (c) 1992, by Sun Microsystems, Inc.
 */

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

#ifndef NSS_BUFLEN_GROUP	/* defined on Linux */
#define NSS_BUFLEN_GROUP        (NSS_LINELEN_GROUP + 200 * sizeof (char *))
#endif /* NSS_BUFLEN_GROUP */
#define NSS_BUFLEN_HOSTS        \
        (NSS_LINELEN_HOSTS + (MAXALIASES + MAXALIASES + 2) * sizeof (char *))
#define NSS_BUFLEN_NETGROUP     (MAXHOSTNAMELEN * 2 + LOGNAME_MAX + 3)
#define NSS_BUFLEN_NETWORKS     NSS_LINELEN_NETWORKS
#ifndef NSS_BUFLEN_PASSWD	/* defined on Linux */
#define NSS_BUFLEN_PASSWD       NSS_LINELEN_PASSWD
#endif /* NSS_BUFLEN_PASSWD */
#define NSS_BUFLEN_PROTOCOLS    NSS_LINELEN_PROTOCOLS
#define NSS_BUFLEN_RPC          NSS_LINELEN_RPC
#define NSS_BUFLEN_SERVICES     NSS_LINELEN_SERVICES
#define NSS_BUFLEN_SHADOW       NSS_LINELEN_SHADOW
#define NSS_BUFLEN_ETHERS       NSS_LINELEN_ETHERS
#define NSS_BUFLEN_BOOTPARAMS   NSS_LINELEN_BOOTPARAMS

#endif /* _LDAP_NSS_LDAP_IRS_H */
