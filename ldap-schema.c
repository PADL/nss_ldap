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

#ifdef AT_OC_MAP
#ifdef HAVE_DB3_DB_185_H
#include <db3/db_185.h>
#else
#ifdef HAVE_DB_185_H
#include <db_185.h>
#elif defined(HAVE_DB1_DB_H)
#include <db1/db.h>
#elif defined(HAVE_DB_H)
#include <db.h>
#endif /* HAVE_DB1_DB_H */
#endif /* HAVE_DB3_DB_H */
#endif /* AT_OC_MAP */

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
static NSS_STATUS setattr (DBT * bufferp, const char **attrp,
			   const char *attrtype);

/* a hack as dbopen(3) returns a static pointer */
static NSS_STATUS
setattr (DBT * bufferp, const char **attrp, const char *attrtype)
{
  size_t len = strlen (attrtype);

  if (bufferp->size < len + 1)
    {
      *attrp = NULL;
      return NSS_TRYAGAIN;
    }

  *attrp = bufferp->data;

  memcpy ((char *) *attrp, attrtype, len + 1);

  bufferp->size -= len + 1;
  bufferp->data += len + 1;

  return NSS_SUCCESS;
}

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

  attrtab[LM_NONE] = NULL;
}

void
init_pwd_attributes (const char ***pwd_attrs)
{
  static const char *__pwd_attrs[ATTRTAB_SIZE];
  static char __pwd_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __pwd_attr_buf, sizeof (__pwd_attr_buf) };

  setattr (&buffer, &__pwd_attrs[0], AT (uid));
  setattr (&buffer, &__pwd_attrs[1], AT (userPassword));
  setattr (&buffer, &__pwd_attrs[2], AT (uidNumber));
  setattr (&buffer, &__pwd_attrs[3], AT (gidNumber));
  setattr (&buffer, &__pwd_attrs[4], AT (cn));
  setattr (&buffer, &__pwd_attrs[5], AT (homeDirectory));
  setattr (&buffer, &__pwd_attrs[6], AT (loginShell));
  setattr (&buffer, &__pwd_attrs[7], AT (gecos));
  setattr (&buffer, &__pwd_attrs[8], AT (description));
  setattr (&buffer, &__pwd_attrs[9], AT (objectClass));
  __pwd_attrs[10] = NULL;
  (*pwd_attrs) = __pwd_attrs;
}

void
init_sp_attributes (const char ***sp_attrs)
{
  static const char *__sp_attrs[ATTRTAB_SIZE];
  static char __sp_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __sp_attr_buf, sizeof (__sp_attr_buf) };

  setattr (&buffer, &__sp_attrs[0], AT (uid));
  setattr (&buffer, &__sp_attrs[1], AT (userPassword));
  setattr (&buffer, &__sp_attrs[2], AT (shadowLastChange));
  setattr (&buffer, &__sp_attrs[3], AT (shadowMax));
  setattr (&buffer, &__sp_attrs[4], AT (shadowMin));
  setattr (&buffer, &__sp_attrs[5], AT (shadowWarning));
  setattr (&buffer, &__sp_attrs[6], AT (shadowInactive));
  setattr (&buffer, &__sp_attrs[7], AT (shadowExpire));
  __sp_attrs[8] = NULL;
  (*sp_attrs) = __sp_attrs;
}

void
init_grp_attributes (const char ***grp_attrs)
{
  static const char *__grp_attrs[ATTRTAB_SIZE];
  static char __grp_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __grp_attr_buf, sizeof (__grp_attr_buf) };

  setattr (&buffer, &__grp_attrs[0], AT (cn));
  setattr (&buffer, &__grp_attrs[1], AT (userPassword));
  setattr (&buffer, &__grp_attrs[2], AT (memberUid));
  setattr (&buffer, &__grp_attrs[3], AT (gidNumber));
#ifdef RFC2307BIS
  setattr (&buffer, &__grp_attrs[4], AT (uniqueMember));
  __grp_attrs[5] = NULL;
#else
  __grp_attrs[4] = NULL;
#endif /* RFC2307BIS */
  (*grp_attrs) = __grp_attrs;
}

void
init_hosts_attributes (const char ***hosts_attrs)
{
  static const char *__hosts_attrs[ATTRTAB_SIZE];
  static char __hosts_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __hosts_attr_buf, sizeof (__hosts_attr_buf) };

  setattr (&buffer, &__hosts_attrs[0], AT (cn));
  setattr (&buffer, &__hosts_attrs[1], AT (ipHostNumber));
  __hosts_attrs[2] = NULL;
  (*hosts_attrs) = __hosts_attrs;
}

void
init_services_attributes (const char ***services_attrs)
{
  static const char *__services_attrs[ATTRTAB_SIZE];
  static char __services_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __services_attr_buf, sizeof (__services_attr_buf) };

  setattr (&buffer, &__services_attrs[0], AT (cn));
  setattr (&buffer, &__services_attrs[1], AT (ipServicePort));
  setattr (&buffer, &__services_attrs[2], AT (ipServiceProtocol));
  __services_attrs[3] = NULL;
  (*services_attrs) = __services_attrs;
}

void
init_network_attributes (const char ***network_attrs)
{
  static const char *__network_attrs[ATTRTAB_SIZE];
  static char __network_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __network_attr_buf, sizeof (__network_attr_buf) };

  setattr (&buffer, &__network_attrs[0], AT (cn));
  setattr (&buffer, &__network_attrs[1], AT (ipNetworkNumber));
  setattr (&buffer, &__network_attrs[2], AT (ipNetmaskNumber));
  __network_attrs[3] = NULL;
  (*network_attrs) = __network_attrs;
}

void
init_proto_attributes (const char ***proto_attrs)
{
  static const char *__proto_attrs[ATTRTAB_SIZE];
  static char __proto_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __proto_attr_buf, sizeof (__proto_attr_buf) };

  setattr (&buffer, &__proto_attrs[0], AT (cn));
  setattr (&buffer, &__proto_attrs[1], AT (ipProtocolNumber));
  __proto_attrs[2] = NULL;
  (*proto_attrs) = __proto_attrs;
}

void
init_rpc_attributes (const char ***rpc_attrs)
{
  static const char *__rpc_attrs[ATTRTAB_SIZE];
  static char __rpc_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __rpc_attr_buf, sizeof (__rpc_attr_buf) };

  setattr (&buffer, &__rpc_attrs[0], AT (cn));
  setattr (&buffer, &__rpc_attrs[1], AT (oncRpcNumber));
  __rpc_attrs[2] = NULL;
  (*rpc_attrs) = __rpc_attrs;
}

void
init_ethers_attributes (const char ***ethers_attrs)
{
  static const char *__ethers_attrs[ATTRTAB_SIZE];
  static char __ethers_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __ethers_attr_buf, sizeof (__ethers_attr_buf) };

  setattr (&buffer, &__ethers_attrs[0], AT (cn));
  setattr (&buffer, &__ethers_attrs[1], AT (macAddress));
  __ethers_attrs[2] = NULL;
  (*ethers_attrs) = __ethers_attrs;
}

void
init_bp_attributes (const char ***bp_attrs)
{
  static const char *__bp_attrs[ATTRTAB_SIZE];
  static char __bp_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __bp_attr_buf, sizeof (__bp_attr_buf) };

  setattr (&buffer, &__bp_attrs[0], AT (cn));
  setattr (&buffer, &__bp_attrs[1], AT (bootParameter));
  __bp_attrs[2] = NULL;
  (*bp_attrs) = __bp_attrs;
}

void
init_alias_attributes (const char ***alias_attrs)
{
  static const char *__alias_attrs[ATTRTAB_SIZE];
  static char __alias_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __alias_attr_buf, sizeof (__alias_attr_buf) };

  setattr (&buffer, &__alias_attrs[0], AT (cn));
  setattr (&buffer, &__alias_attrs[1], AT (rfc822MailMember));
  __alias_attrs[2] = NULL;
  (*alias_attrs) = __alias_attrs;
}

void
init_netgrp_attributes (const char ***netgrp_attrs)
{
  static const char *__netgrp_attrs[ATTRTAB_SIZE];
  static char __netgrp_attr_buf[ATTRBUF_SIZE];
  DBT buffer = { __netgrp_attr_buf, sizeof (__netgrp_attr_buf) };

  setattr (&buffer, &__netgrp_attrs[0], AT (cn));
  setattr (&buffer, &__netgrp_attrs[1], AT (nisNetgroupTriple));
  setattr (&buffer, &__netgrp_attrs[2], AT (memberNisNetgroup));
  __netgrp_attrs[3] = NULL;
  (*netgrp_attrs) = __netgrp_attrs;
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
  attrtab[LM_NONE] = NULL;
}

#endif /* AT_OC_MAP */
