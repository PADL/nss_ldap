/* Copyright (C) 2000-2001 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2000.

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

static char rcsId[] = "$Id$";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#ifdef HAVE_THREAD_H
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <netdb.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"

#ifdef HAVE_PORT_AFTER_H
#nclude <port_after.h>
#endif

static const char *pw_attributes[] =
{AT (uid), AT (userPassword),
#ifdef AUTHPASSWORD
 AT (authPassword),
#endif				/* AUTHPASSWORD */
 AT (uidNumber), AT (gidNumber),
 AT (cn), AT (homeDirectory),
 AT (loginShell), AT (gecos),
 AT (description), AT (objectClass),
 NULL};

static const char *sp_attributes[] =
{AT (uid), AT (userPassword),
#ifdef AUTHPASSWORD
 AT (authPassword),
#endif				/* AUTHPASSWORD */
 AT (shadowLastChange), AT (shadowMax),
 AT (shadowMin), AT (shadowWarning),
 AT (shadowInactive), AT (shadowExpire),
 NULL};

static const char *gr_attributes[] =
{AT (cn), AT (userPassword),
#ifdef AUTHPASSWORD
 AT (authPassword),
#endif				/* AUTHPASSWORD */
 AT (memberUid),
#ifdef RFC2307BIS
 AT (uniqueMember),
#endif				/* RFC2307BIS */
 AT (gidNumber), NULL};

static const char *host_attributes[] =
{AT (cn), AT (ipHostNumber), NULL};

static const char *serv_attributes[] =
{AT (cn), AT (ipServicePort),
 AT (ipServiceProtocol), NULL};

static const char *net_attributes[] =
{AT (cn), AT (ipNetworkNumber),
 NULL};

static const char *proto_attributes[] =
{AT (cn), AT (ipProtocolNumber),
 NULL};

static const char *rpc_attributes[] =
{AT (cn), AT (oncRpcNumber), NULL};

static const char *ether_attributes[] =
{AT (cn), AT (macAddress), NULL};

static const char *bp_attributes[] =
{AT (cn), AT (bootParameter), NULL};

static const char *alias_attributes[] =
{AT (cn), AT (rfc822MailMember), NULL};

static const char *netgr_attributes[] =
{AT (cn), AT (nisNetgroupTriple), AT (memberNisNetgroup), NULL};

#ifdef __GNUC__
const char **_nss_ldap_attrtab[] =
{
  [LM_PASSWD] = pw_attributes,
  [LM_SHADOW] = sp_attributes,
  [LM_GROUP] = gr_attributes,
  [LM_HOSTS] = host_attributes,
  [LM_SERVICES] = serv_attributes,
  [LM_NETWORKS] = net_attributes,
  [LM_PROTOCOLS] = proto_attributes,
  [LM_RPC] = rpc_attributes,
  [LM_ETHERS] = ether_attributes,
  [LM_NETMASKS] = net_attributes,
  [LM_BOOTPARAMS] = bp_attributes,
  [LM_ALIASES] = alias_attributes,
  [LM_NETGROUP] = netgr_attributes,
  [LM_NONE] = NULL
};
#else
const char **_nss_ldap_attrtab[] =
/* These must be ordered per selectors in ldap-nss.h */
{pw_attributes, sp_attributes,
 gr_attributes,
 host_attributes, serv_attributes,
 net_attributes, proto_attributes,
 rpc_attributes, ether_attributes,
 net_attributes, bp_attributes,
 alias_attributes, netgr_attributes,
 NULL
};
#endif /* __GNUC__ */
