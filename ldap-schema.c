/* Copyright (C) 1997-2003 Luke Howard.
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

static char rcsId[] =
  "$Id$";

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
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif /* HAVE_SNPRINTF */
#include "ldap-nss.h"
#include "ldap-schema.h"

#ifdef HAVE_PORT_AFTER_H
#nclude <port_after.h>
#endif


/**
 * declare filters formerly declared in ldap-*.h
 */

/* rfc822 mail aliases */
char _nss_ldap_filt_getaliasbyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getaliasent[LDAP_FILT_MAXSIZ];

/* boot parameters */
char _nss_ldap_filt_getbootparamsbyname[LDAP_FILT_MAXSIZ];

/* MAC address mappings */
char _nss_ldap_filt_gethostton[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getntohost[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getetherent[LDAP_FILT_MAXSIZ];

/* groups */
char _nss_ldap_filt_getgrnam[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgrgid[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgrent[LDAP_FILT_MAXSIZ];
#ifdef RFC2307BIS
char _nss_ldap_filt_getgroupsbymemberanddn[LDAP_FILT_MAXSIZ];
#endif /* RFC2307BIS */
char _nss_ldap_filt_getgroupsbymember[LDAP_FILT_MAXSIZ];

/* IP hosts */
char _nss_ldap_filt_gethostbyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_gethostbyaddr[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_gethostent[LDAP_FILT_MAXSIZ];

/* IP networks */
char _nss_ldap_filt_getnetbyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getnetbyaddr[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getnetent[LDAP_FILT_MAXSIZ];

/* IP protocols */
char _nss_ldap_filt_getprotobyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getprotobynumber[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getprotoent[LDAP_FILT_MAXSIZ];

/* users */
char _nss_ldap_filt_getpwnam[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getpwuid[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getpwent[LDAP_FILT_MAXSIZ];

/* RPCs */
char _nss_ldap_filt_getrpcbyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getrpcbynumber[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getrpcent[LDAP_FILT_MAXSIZ];

/* IP services */
char _nss_ldap_filt_getservbyname[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getservbynameproto[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getservbyport[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getservbyportproto[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getservent[LDAP_FILT_MAXSIZ];

/* shadow users */
char _nss_ldap_filt_getspnam[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getspent[LDAP_FILT_MAXSIZ];

/* netgroups */
char _nss_ldap_filt_getnetgrent[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_innetgr[LDAP_FILT_MAXSIZ];

/**
 * lookup filter initialization
 */
void
_nss_ldap_init_filters ()
{
  /* rfc822 mail aliases */
  snprintf (_nss_ldap_filt_getaliasbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (nisMailAlias), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getaliasent, LDAP_FILT_MAXSIZ,
	    "(objectclass=%s)", OC (nisMailAlias));

  /* boot parameters */
  snprintf (_nss_ldap_filt_getbootparamsbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (bootableDevice), AT (cn), "%d");

  /* MAC address mappings */
  snprintf (_nss_ldap_filt_gethostton, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ieee802Device), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getntohost, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ieee802Device), AT (macAddress),
	    "%s");
  snprintf (_nss_ldap_filt_getetherent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (ieee802Device));

  /* groups */
  snprintf (_nss_ldap_filt_getgrnam, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (posixGroup), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getgrgid, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (posixGroup), AT (gidNumber),
	    "%d");
  snprintf (_nss_ldap_filt_getgrent, LDAP_FILT_MAXSIZ, "(&(objectclass=%s))",
	    OC (posixGroup));
#ifdef RFC2307BIS
  snprintf (_nss_ldap_filt_getgroupsbymemberanddn, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(|(%s=%s)(%s=%s)))",
	    OC (posixGroup), AT (memberUid), "%s", AT (uniqueMember), "%s");
#endif /* RFC2307BIS */
  snprintf (_nss_ldap_filt_getgroupsbymember, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (posixGroup), AT (memberUid),
	    "%s");

  /* IP hosts */
  snprintf (_nss_ldap_filt_gethostbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipHost), AT (cn), "%s");
  snprintf (_nss_ldap_filt_gethostbyaddr, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipHost), AT (ipHostNumber),
	    "%s");
  snprintf (_nss_ldap_filt_gethostent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (ipHost));

  /* IP networks */
  snprintf (_nss_ldap_filt_getnetbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipNetwork), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getnetbyaddr, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipNetwork),
	    AT (ipNetworkNumber), "%s");
  snprintf (_nss_ldap_filt_getnetent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (ipNetwork));

  /* IP protocols */
  snprintf (_nss_ldap_filt_getprotobyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipProtocol), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getprotobynumber, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipProtocol),
	    AT (ipProtocolNumber), "%d");
  snprintf (_nss_ldap_filt_getprotoent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (ipProtocol));

  /* users */
  snprintf (_nss_ldap_filt_getpwnam, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (posixAccount), AT (uid), "%s");
  snprintf (_nss_ldap_filt_getpwuid, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))",
	    OC (posixAccount), AT (uidNumber), "%d");
  snprintf (_nss_ldap_filt_getpwent, LDAP_FILT_MAXSIZ,
	    "(objectclass=%s)", OC (posixAccount));

  /* RPCs */
  snprintf (_nss_ldap_filt_getrpcbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (oncRpc), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getrpcbynumber, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (oncRpc), AT (oncRpcNumber),
	    "%d");
  snprintf (_nss_ldap_filt_getrpcent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (oncRpc));

  /* IP services */
  snprintf (_nss_ldap_filt_getservbyname, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipService), AT (cn), "%s");
  snprintf (_nss_ldap_filt_getservbynameproto, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s)(%s=%s))",
	    OC (ipService), AT (cn), "%s", AT (ipServiceProtocol), "%s");
  snprintf (_nss_ldap_filt_getservbyport, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (ipService), AT (ipServicePort),
	    "%d");
  snprintf (_nss_ldap_filt_getservbyportproto, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s)(%s=%s))", OC (ipService),
	    AT (ipServicePort), "%d", AT (ipServiceProtocol), "%s");
  snprintf (_nss_ldap_filt_getservent, LDAP_FILT_MAXSIZ, "(objectclass=%s)",
	    OC (ipService));

  /* shadow users */
  snprintf (_nss_ldap_filt_getspnam, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (shadowAccount), AT (uid), "%s");
  snprintf (_nss_ldap_filt_getspent, LDAP_FILT_MAXSIZ,
	    "(objectclass=%s)", OC (shadowAccount));

  /* netgroups */
  snprintf (_nss_ldap_filt_getnetgrent, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (nisNetgroup), AT (cn), "%s");
  snprintf (_nss_ldap_filt_innetgr, LDAP_FILT_MAXSIZ,
	    "(&(objectclass=%s)(%s=%s))", OC (nisNetgroup), AT (memberNisNetgroup), "%s");
}

#ifdef AT_OC_MAP
static void init_pwd_attributes (const char ***pwd_attrs);
static void init_sp_attributes (const char ***sp_attrs);
static void init_grp_attributes (const char ***grp_attrs);
static void init_hosts_attributes (const char ***hosts_attrs);
static void init_services_attributes (const char ***services_attrs);
static void init_network_attributes (const char ***network_attrs);
static void init_proto_attributes (const char ***proto_attrs);
static void init_rpc_attributes (const char ***rpc_attrs);
static void init_ethers_attributes (const char ***ethers_attrs);
static void init_bp_attributes (const char ***bp_attrs);
static void init_alias_attributes (const char ***alias_attrs);
static void init_netgrp_attributes (const char ***netgrp_attrs);
static void init_automount_attributes (const char ***automount_attrs);

/**
 * attribute table initialization routines
 */
void
_nss_ldap_init_attributes (const char ***attrtab)
{
  init_pwd_attributes (&attrtab[LM_PASSWD]);
  init_sp_attributes (&attrtab[LM_SHADOW]);
  init_grp_attributes (&attrtab[LM_GROUP]);
  init_hosts_attributes (&attrtab[LM_HOSTS]);
  init_services_attributes (&attrtab[LM_SERVICES]);
  init_network_attributes (&attrtab[LM_NETWORKS]);
  init_proto_attributes (&attrtab[LM_PROTOCOLS]);
  init_rpc_attributes (&attrtab[LM_RPC]);
  init_ethers_attributes (&attrtab[LM_ETHERS]);
  init_network_attributes (&attrtab[LM_NETMASKS]);
  init_bp_attributes (&attrtab[LM_BOOTPARAMS]);
  init_alias_attributes (&attrtab[LM_ALIASES]);
  init_netgrp_attributes (&attrtab[LM_NETGROUP]);
  init_automount_attributes (&attrtab[LM_AUTOMOUNT]);

  attrtab[LM_NONE] = NULL;
}

void
init_pwd_attributes (const char ***pwd_attrs)
{
  static const char *__pwd_attrs[ATTRTAB_SIZE + 1];

  (*pwd_attrs) = __pwd_attrs;

  (*pwd_attrs)[0] = AT (uid);
  (*pwd_attrs)[1] = AT (userPassword);
  (*pwd_attrs)[2] = AT (uidNumber);
  (*pwd_attrs)[3] = AT (gidNumber);
  (*pwd_attrs)[4] = AT (cn);
  (*pwd_attrs)[5] = AT (homeDirectory);
  (*pwd_attrs)[6] = AT (loginShell);
  (*pwd_attrs)[7] = AT (gecos);
  (*pwd_attrs)[8] = AT (description);
  (*pwd_attrs)[9] = AT (objectClass);
  (*pwd_attrs)[10] = NULL;
}

void
init_sp_attributes (const char ***sp_attrs)
{
  static const char *__sp_attrs[ATTRTAB_SIZE + 1];

  (*sp_attrs) = __sp_attrs;

  (*sp_attrs)[0] = (char *) AT (uid);
  (*sp_attrs)[1] = (char *) AT (userPassword);
  (*sp_attrs)[2] = (char *) AT (shadowLastChange);
  (*sp_attrs)[3] = (char *) AT (shadowMax);
  (*sp_attrs)[4] = (char *) AT (shadowMin);
  (*sp_attrs)[5] = (char *) AT (shadowWarning);
  (*sp_attrs)[6] = (char *) AT (shadowInactive);
  (*sp_attrs)[7] = (char *) AT (shadowExpire);
  (*sp_attrs)[8] = (char *) AT (shadowFlag);
  (*sp_attrs)[9] = NULL;
}

void
init_grp_attributes (const char ***grp_attrs)
{
  int i = 0;
  static const char *__grp_attrs[ATTRTAB_SIZE + 1];

  (*grp_attrs) = __grp_attrs;

  (*grp_attrs)[i++] = (char *) AT (cn);
  (*grp_attrs)[i++] = (char *) AT (userPassword);
  (*grp_attrs)[i++] = (char *) AT (memberUid);
#ifdef RFC2307BIS
  (*grp_attrs)[i++] = (char *) AT (uniqueMember);
#endif /* RFC2307BIS */
  (*grp_attrs)[i++] = (char *) AT (gidNumber);
  (*grp_attrs)[i] = NULL;
}

void
init_hosts_attributes (const char ***hosts_attrs)
{
  static const char *__hosts_attrs[ATTRTAB_SIZE + 1];

  (*hosts_attrs) = __hosts_attrs;

  (*hosts_attrs)[0] = (char *) AT (cn);
  (*hosts_attrs)[1] = (char *) AT (ipHostNumber);
  (*hosts_attrs)[2] = NULL;
}

void
init_services_attributes (const char ***services_attrs)
{
  static const char *__services_attrs[ATTRTAB_SIZE + 1];

  (*services_attrs) = __services_attrs;

  (*services_attrs)[0] = AT (cn);
  (*services_attrs)[1] = AT (ipServicePort);
  (*services_attrs)[2] = AT (ipServiceProtocol);
  (*services_attrs)[3] = NULL;
}

void
init_network_attributes (const char ***network_attrs)
{
  static const char *__network_attrs[ATTRTAB_SIZE + 1];

  (*network_attrs) = __network_attrs;

  (*network_attrs)[0] = AT (cn);
  (*network_attrs)[1] = AT (ipNetworkNumber);
  (*network_attrs)[2] = AT (ipNetmaskNumber);
  (*network_attrs)[3] = NULL;
}

void
init_proto_attributes (const char ***proto_attrs)
{
  static const char *__proto_attrs[ATTRTAB_SIZE + 1];

  (*proto_attrs) = __proto_attrs;

  (*proto_attrs)[0] = AT (cn);
  (*proto_attrs)[1] = AT (ipProtocolNumber);
  (*proto_attrs)[2] = NULL;
}

void
init_rpc_attributes (const char ***rpc_attrs)
{
  static const char *__rpc_attrs[ATTRTAB_SIZE + 1];

  (*rpc_attrs) = __rpc_attrs;

  (*rpc_attrs)[0] = AT (cn);
  (*rpc_attrs)[1] = AT (oncRpcNumber);
  (*rpc_attrs)[2] = NULL;
}

void
init_ethers_attributes (const char ***ethers_attrs)
{
  static const char *__ethers_attrs[ATTRTAB_SIZE + 1];

  (*ethers_attrs) = __ethers_attrs;

  (*ethers_attrs)[0] = AT (cn);
  (*ethers_attrs)[1] = AT (macAddress);
  (*ethers_attrs)[2] = NULL;
}

void
init_bp_attributes (const char ***bp_attrs)
{
  static const char *__bp_attrs[ATTRTAB_SIZE + 1];

  (*bp_attrs) = __bp_attrs;

  (*bp_attrs)[0] = AT (cn);
  (*bp_attrs)[1] = AT (bootParameter);
  (*bp_attrs)[2] = NULL;
}

void
init_alias_attributes (const char ***alias_attrs)
{
  static const char *__alias_attrs[ATTRTAB_SIZE + 1];

  (*alias_attrs) = __alias_attrs;

  (*alias_attrs)[0] = AT (cn);
  (*alias_attrs)[1] = AT (rfc822MailMember);
  (*alias_attrs)[2] = NULL;
}

void
init_netgrp_attributes (const char ***netgrp_attrs)
{
  static const char *__netgrp_attrs[ATTRTAB_SIZE + 1];

  (*netgrp_attrs) = __netgrp_attrs;

  (*netgrp_attrs)[0] = AT (cn);
  (*netgrp_attrs)[1] = AT (nisNetgroupTriple);
  (*netgrp_attrs)[2] = AT (memberNisNetgroup);
  (*netgrp_attrs)[3] = NULL;
}

void
init_automount_attributes (const char ***automount_attrs)
{
  static const char *__automount_attrs[ATTRTAB_SIZE + 1];

  (*automount_attrs) = __automount_attrs;

  (*automount_attrs)[0] = AT (cn);
  (*automount_attrs)[1] = AT (nisMapEntry);
  (*automount_attrs)[2] = AT (nisMapName);
  (*automount_attrs)[3] = AT (description);
  (*automount_attrs)[4] = NULL;
}

#else /* AT_OC_MAP */

static const char *pwd_attributes[] = { AT (uid), AT (userPassword),
  AT (uidNumber), AT (gidNumber),
  AT (cn), AT (homeDirectory),
  AT (loginShell), AT (gecos),
  AT (description), AT (objectClass),
  NULL
};

static const char *sp_attributes[] = { AT (uid), AT (userPassword),
  AT (shadowLastChange), AT (shadowMax),
  AT (shadowMin), AT (shadowWarning),
  AT (shadowInactive), AT (shadowExpire),
  NULL
};

static const char *grp_attributes[] = { AT (cn), AT (userPassword),
  AT (memberUid),
#ifdef RFC2307BIS
  AT (uniqueMember),
#endif				/* RFC2307BIS */
  AT (gidNumber), NULL
};

static const char *hosts_attributes[] = { AT (cn), AT (ipHostNumber), NULL };

static const char *services_attributes[] = { AT (cn), AT (ipServicePort),
  AT (ipServiceProtocol), NULL
};

static const char *network_attributes[] = { AT (cn), AT (ipNetworkNumber),
  NULL
};

static const char *proto_attributes[] = { AT (cn), AT (ipProtocolNumber),
  NULL
};

static const char *rpc_attributes[] = { AT (cn), AT (oncRpcNumber), NULL };

static const char *ethers_attributes[] = { AT (cn), AT (macAddress), NULL };

static const char *bp_attributes[] = { AT (cn), AT (bootParameter), NULL };

static const char *alias_attributes[] =
  { AT (cn), AT (rfc822MailMember), NULL };

static const char *netgrp_attributes[] =
  { AT (cn), AT (nisNetgroupTriple), AT (memberNisNetgroup), NULL };

static const char *automount_attributes[] =
  { AT (cn), AT (nisMapEntry), AT (nisMapName), AT (description), NULL };

void
_nss_ldap_init_attributes (const char ***attrtab)
{
  attrtab[LM_PASSWD] = pwd_attributes;
  attrtab[LM_SHADOW] = sp_attributes;
  attrtab[LM_GROUP] = grp_attributes;
  attrtab[LM_HOSTS] = hosts_attributes;
  attrtab[LM_SERVICES] = services_attributes;
  attrtab[LM_NETWORKS] = network_attributes;
  attrtab[LM_PROTOCOLS] = proto_attributes;
  attrtab[LM_RPC] = rpc_attributes;
  attrtab[LM_ETHERS] = ethers_attributes;
  attrtab[LM_NETMASKS] = network_attributes;
  attrtab[LM_BOOTPARAMS] = bp_attributes;
  attrtab[LM_ALIASES] = alias_attributes;
  attrtab[LM_NETGROUP] = netgrp_attributes;
  attrtab[LM_AUTOMOUNT] = automount_attributes;
  attrtab[LM_NONE] = NULL;
}

#endif /* AT_OC_MAP */
