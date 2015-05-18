/* Copyright (C) 1997-2005 Luke Howard.
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

#if defined(HAVE_THREAD_H) && !defined(_AIX)
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <assert.h>
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
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
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
char _nss_ldap_filt_getgroupsbymemberanddn[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getgroupsbydn[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getpwnam_groupsbymember[LDAP_FILT_MAXSIZ];
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

/* automount */
char _nss_ldap_filt_setautomntent[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getautomntent[LDAP_FILT_MAXSIZ];
char _nss_ldap_filt_getautomntbyname[LDAP_FILT_MAXSIZ];

#define PUT_CHAR(c) \
  do { \
    if (buffer < buffer_end) \
      *(buffer++) = c; \
  } while (0)

#define PUT_STR(str) \
  do { \
    char const* const s = str; \
    size_t const s_size = strlen (s); \
    size_t const space_left = buffer_end - buffer; \
    size_t const copy_size = (s_size < space_left ? s_size : space_left); \
    memcpy (buffer, s, copy_size); \
    buffer += copy_size; \
  } while (0)

#define FILL(filter_buffer) \
  do { \
    char* buffer = filter_buffer; \
    char* const buffer_end = buffer + LDAP_FILT_MAXSIZ

#define FILL_END \
    assert (buffer < buffer_end); \
    *(buffer < buffer_end ? buffer : buffer_end - 1) = '\0'; \
  } while (0)

#define FILTER \
  do { \
    PUT_CHAR ('(')

#define FILTER_END \
    PUT_CHAR (')'); \
  } while (0)

#define AND_FILTER \
  FILTER; \
    PUT_CHAR ('&')

#define OR_FILTER \
  FILTER; \
    PUT_CHAR ('|')

#define ITEM(attr, matchingrule, filtertype, assertionvalue) \
  do { \
    char const* const mr = matchingrule; \
    PUT_STR (attr); \
    if (mr) \
    { \
      PUT_CHAR (':'); \
      PUT_STR (mr); \
      PUT_CHAR (':'); \
    } \
    PUT_STR (#filtertype); \
    PUT_STR (assertionvalue); \
  } while (0)

#define ITEM_FILTER(map, at, assertionvalue) \
  FILTER; \
    ITEM (ATM (map, at), MRM (map, at), =, assertionvalue); \
  FILTER_END

#define FIXED_ITEM_FILTERM(map, at, oc) \
  ITEM_FILTER (map, at, OC (oc))

#define FIXED_ITEM_FILTER(at, oc) \
  FIXED_ITEM_FILTERM (LM_NONE, at, oc)

#define QUERY_ITEM_FILTERM(map, at, specifier) \
  ITEM_FILTER (map, at, specifier)

#define QUERY_ITEM_FILTER(at, specifier) \
  QUERY_ITEM_FILTERM (LM_NONE, at, specifier)

/**
 * lookup filter initialization
 */
void
_nss_ldap_init_filters ()
{
  /* rfc822 mail aliases */
  FILL (_nss_ldap_filt_getaliasbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, nisMailAlias);
      QUERY_ITEM_FILTERM (LM_ALIASES, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getaliasent);
    FIXED_ITEM_FILTER (objectClass, nisMailAlias);
  FILL_END;

  /* boot parameters */
  FILL (_nss_ldap_filt_getbootparamsbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, bootableDevice);
      QUERY_ITEM_FILTERM (LM_BOOTPARAMS, cn, "%d");
    FILTER_END;
  FILL_END;

  /* MAC address mappings */
  FILL (_nss_ldap_filt_gethostton);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ieee802Device);
      QUERY_ITEM_FILTERM (LM_ETHERS, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getntohost);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ieee802Device);
      OR_FILTER;
        QUERY_ITEM_FILTER (macAddress, "%s");
        QUERY_ITEM_FILTER (macAddress, "%s");
      FILTER_END;
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getetherent);
    FIXED_ITEM_FILTER (objectClass, ieee802Device);
  FILL_END;

  /* groups */
  FILL (_nss_ldap_filt_getgrnam);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixGroup);
      QUERY_ITEM_FILTERM (LM_GROUP, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getgrgid);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixGroup);
      QUERY_ITEM_FILTERM (LM_GROUP, gidNumber, "%d");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getgrent);
    FIXED_ITEM_FILTER (objectClass, posixGroup);
  FILL_END;
  FILL (_nss_ldap_filt_getgroupsbymemberanddn);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixGroup);
      OR_FILTER;
        QUERY_ITEM_FILTER (memberUid, "%s");
        QUERY_ITEM_FILTER (uniqueMember, "%s");
      FILTER_END;
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getgroupsbydn);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixGroup);
      QUERY_ITEM_FILTER (uniqueMember, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getpwnam_groupsbymember);
    OR_FILTER;
      AND_FILTER;
        FIXED_ITEM_FILTER (objectClass, posixGroup);
        QUERY_ITEM_FILTER (memberUid, "%s");
      FILTER_END;
      AND_FILTER;
        FIXED_ITEM_FILTER (objectClass, posixAccount);
        QUERY_ITEM_FILTERM (LM_PASSWD, uid, "%s");
      FILTER_END;
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getgroupsbymember);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixGroup);
      QUERY_ITEM_FILTER (memberUid, "%s");
    FILTER_END;
  FILL_END;

  /* IP hosts */
  FILL (_nss_ldap_filt_gethostbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipHost);
      QUERY_ITEM_FILTERM (LM_HOSTS, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_gethostbyaddr);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipHost);
      QUERY_ITEM_FILTER (ipHostNumber, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_gethostent);
    FIXED_ITEM_FILTER (objectClass, ipHost);
  FILL_END;

  /* IP networks */
  FILL (_nss_ldap_filt_getnetbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipNetwork);
      QUERY_ITEM_FILTERM (LM_NETWORKS, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getnetbyaddr);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipNetwork);
      QUERY_ITEM_FILTER (ipNetworkNumber, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getnetent);
    FIXED_ITEM_FILTER (objectClass, ipNetwork);
  FILL_END;

  /* IP protocols */
  FILL (_nss_ldap_filt_getprotobyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipProtocol);
      QUERY_ITEM_FILTERM (LM_PROTOCOLS, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getprotobynumber);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipProtocol);
      QUERY_ITEM_FILTER (ipProtocolNumber, "%d");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getprotoent);
    FIXED_ITEM_FILTER (objectClass, ipProtocol);
  FILL_END;

  /* users */
  FILL (_nss_ldap_filt_getpwnam);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixAccount);
      QUERY_ITEM_FILTERM (LM_PASSWD, uid, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getpwuid);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, posixAccount);
      QUERY_ITEM_FILTER (uidNumber, "%d");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getpwent);
    FIXED_ITEM_FILTER (objectClass, posixAccount);
  FILL_END;

  /* RPCs */
  FILL (_nss_ldap_filt_getrpcbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, oncRpc);
      QUERY_ITEM_FILTERM (LM_RPC, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getrpcbynumber);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, oncRpc);
      QUERY_ITEM_FILTER (oncRpcNumber, "%d");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getrpcent);
    FIXED_ITEM_FILTER (objectClass, oncRpc);
  FILL_END;

  /* IP services */
  FILL (_nss_ldap_filt_getservbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipService);
      QUERY_ITEM_FILTERM (LM_SERVICES, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getservbynameproto);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipService);
      QUERY_ITEM_FILTERM (LM_SERVICES, cn, "%s");
      QUERY_ITEM_FILTER (ipServiceProtocol, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getservbyport);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipService);
      QUERY_ITEM_FILTER (ipServicePort, "%d");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getservbyportproto);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, ipService);
      QUERY_ITEM_FILTER (ipServicePort, "%d");
      QUERY_ITEM_FILTER (ipServiceProtocol, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getservent);
    FIXED_ITEM_FILTER (objectClass, ipService);
  FILL_END;

  /* shadow users */
  FILL (_nss_ldap_filt_getspnam);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, shadowAccount);
      QUERY_ITEM_FILTERM (LM_SHADOW, uid, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getspent);
    FIXED_ITEM_FILTER (objectClass, shadowAccount);
  FILL_END;

  /* netgroups */
  FILL (_nss_ldap_filt_getnetgrent);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, nisNetgroup);
      QUERY_ITEM_FILTERM (LM_NETGROUP, cn, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_innetgr);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, nisNetgroup);
      QUERY_ITEM_FILTER (memberNisNetgroup, "%s");
    FILTER_END;
  FILL_END;

  /* automounts */
  FILL (_nss_ldap_filt_setautomntent);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, automountMap);
      QUERY_ITEM_FILTER (automountMapName, "%s");
    FILTER_END;
  FILL_END;
  FILL (_nss_ldap_filt_getautomntent);
    FIXED_ITEM_FILTER (objectClass, automount);
  FILL_END;
  FILL (_nss_ldap_filt_getautomntbyname);
    AND_FILTER;
      FIXED_ITEM_FILTER (objectClass, automount);
      QUERY_ITEM_FILTER (automountKey, "%s");
    FILTER_END;
  FILL_END;
}

static void init_pwd_attributes (const char ***pwd_attrs);
static void init_sp_attributes (const char ***sp_attrs);
static void init_grp_attributes (const char ***grp_attrs, int skipmembers);
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
_nss_ldap_init_attributes (const char ***attrtab, int skipmembers)
{
  init_pwd_attributes (&attrtab[LM_PASSWD]);
  init_sp_attributes (&attrtab[LM_SHADOW]);
  init_grp_attributes (&attrtab[LM_GROUP], skipmembers);
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

static void
init_pwd_attributes (const char ***pwd_attrs)
{
  int i = 0;
  static const char *__pwd_attrs[ATTRTAB_SIZE + 1];

  (*pwd_attrs) = __pwd_attrs;

  (*pwd_attrs)[i++] = ATM (LM_PASSWD, uid);
  (*pwd_attrs)[i++] = ATM (LM_PASSWD, userPassword);
  (*pwd_attrs)[i++] = AT (uidNumber);
  (*pwd_attrs)[i++] = ATM (LM_PASSWD, gidNumber);
  (*pwd_attrs)[i++] = ATM (LM_PASSWD, cn);
  (*pwd_attrs)[i++] = AT (homeDirectory);
  (*pwd_attrs)[i++] = AT (loginShell);
  (*pwd_attrs)[i++] = AT (gecos);
  (*pwd_attrs)[i++] = ATM (LM_PASSWD, description);
  (*pwd_attrs)[i++] = AT (objectClass);
#ifdef HAVE_PASSWD_PW_CHANGE
  (*pwd_attrs)[i++] = AT (shadowLastChange);
  (*pwd_attrs)[i++] = AT (shadowMax);
#endif /* HAVE_PASSWD_PW_CHANGE */
#ifdef HAVE_PASSWD_PW_EXPIRE
  (*pwd_attrs)[i++] = AT (shadowExpire);
#endif /* HAVE_PASSWD_PW_EXPIRE */
#ifdef HAVE_LOGIN_CLASSES
  (*pwd_attrs)[i++] = AT (loginClass);
#endif
  (*pwd_attrs)[i] = NULL;
}

static void
init_sp_attributes (const char ***sp_attrs)
{
  static const char *__sp_attrs[ATTRTAB_SIZE + 1];

  (*sp_attrs) = __sp_attrs;

  (*sp_attrs)[0] = (char *) ATM (LM_SHADOW, uid);
  (*sp_attrs)[1] = (char *) ATM (LM_SHADOW, userPassword);
  (*sp_attrs)[2] = (char *) AT (shadowLastChange);
  (*sp_attrs)[3] = (char *) AT (shadowMax);
  (*sp_attrs)[4] = (char *) AT (shadowMin);
  (*sp_attrs)[5] = (char *) AT (shadowWarning);
  (*sp_attrs)[6] = (char *) AT (shadowInactive);
  (*sp_attrs)[7] = (char *) AT (shadowExpire);
  (*sp_attrs)[8] = (char *) AT (shadowFlag);
  (*sp_attrs)[9] = NULL;
}

static void
init_grp_attributes (const char ***grp_attrs, int skipmembers)
{
  int i = 0;
  static const char *__grp_attrs[ATTRTAB_SIZE + 1];

  (*grp_attrs) = __grp_attrs;

  (*grp_attrs)[i++] = (char *) ATM (LM_GROUP, cn);
  (*grp_attrs)[i++] = (char *) ATM (LM_GROUP, userPassword);
  if (!skipmembers)
    {
      (*grp_attrs)[i++] = (char *) AT (memberUid);
      if (_nss_ldap_test_config_flag (NSS_LDAP_FLAGS_RFC2307BIS))
        (*grp_attrs)[i++] = (char *) AT (uniqueMember);
    }
  (*grp_attrs)[i++] = (char *) ATM (LM_GROUP, gidNumber);
  (*grp_attrs)[i] = NULL;
}

static void
init_hosts_attributes (const char ***hosts_attrs)
{
  static const char *__hosts_attrs[ATTRTAB_SIZE + 1];

  (*hosts_attrs) = __hosts_attrs;

  (*hosts_attrs)[0] = (char *) ATM (LM_HOSTS, cn);
  (*hosts_attrs)[1] = (char *) AT (ipHostNumber);
  (*hosts_attrs)[2] = NULL;
}

static void
init_services_attributes (const char ***services_attrs)
{
  static const char *__services_attrs[ATTRTAB_SIZE + 1];

  (*services_attrs) = __services_attrs;

  (*services_attrs)[0] = ATM (LM_SERVICES, cn);
  (*services_attrs)[1] = AT (ipServicePort);
  (*services_attrs)[2] = AT (ipServiceProtocol);
  (*services_attrs)[3] = NULL;
}

static void
init_network_attributes (const char ***network_attrs)
{
  static const char *__network_attrs[ATTRTAB_SIZE + 1];

  (*network_attrs) = __network_attrs;

  (*network_attrs)[0] = ATM (LM_NETWORKS, cn);
  (*network_attrs)[1] = AT (ipNetworkNumber);
  (*network_attrs)[2] = AT (ipNetmaskNumber);
  (*network_attrs)[3] = NULL;
}

static void
init_proto_attributes (const char ***proto_attrs)
{
  static const char *__proto_attrs[ATTRTAB_SIZE + 1];

  (*proto_attrs) = __proto_attrs;

  (*proto_attrs)[0] = ATM (LM_PROTOCOLS, cn);
  (*proto_attrs)[1] = AT (ipProtocolNumber);
  (*proto_attrs)[2] = NULL;
}

static void
init_rpc_attributes (const char ***rpc_attrs)
{
  static const char *__rpc_attrs[ATTRTAB_SIZE + 1];

  (*rpc_attrs) = __rpc_attrs;

  (*rpc_attrs)[0] = ATM (LM_RPC, cn);
  (*rpc_attrs)[1] = AT (oncRpcNumber);
  (*rpc_attrs)[2] = NULL;
}

static void
init_ethers_attributes (const char ***ethers_attrs)
{
  static const char *__ethers_attrs[ATTRTAB_SIZE + 1];

  (*ethers_attrs) = __ethers_attrs;

  (*ethers_attrs)[0] = ATM (LM_ETHERS, cn);
  (*ethers_attrs)[1] = AT (macAddress);
  (*ethers_attrs)[2] = NULL;
}

static void
init_bp_attributes (const char ***bp_attrs)
{
  static const char *__bp_attrs[ATTRTAB_SIZE + 1];

  (*bp_attrs) = __bp_attrs;

  (*bp_attrs)[0] = ATM (LM_BOOTPARAMS, cn);
  (*bp_attrs)[1] = AT (bootParameter);
  (*bp_attrs)[2] = NULL;
}

static void
init_alias_attributes (const char ***alias_attrs)
{
  static const char *__alias_attrs[ATTRTAB_SIZE + 1];

  (*alias_attrs) = __alias_attrs;

  (*alias_attrs)[0] = ATM (LM_ALIASES, cn);
  (*alias_attrs)[1] = AT (rfc822MailMember);
  (*alias_attrs)[2] = NULL;
}

static void
init_netgrp_attributes (const char ***netgrp_attrs)
{
  static const char *__netgrp_attrs[ATTRTAB_SIZE + 1];

  (*netgrp_attrs) = __netgrp_attrs;

  (*netgrp_attrs)[0] = ATM (LM_NETGROUP, cn);
  (*netgrp_attrs)[1] = AT (nisNetgroupTriple);
  (*netgrp_attrs)[2] = AT (memberNisNetgroup);
  (*netgrp_attrs)[3] = NULL;
}

static void
init_automount_attributes (const char ***automount_attrs)
{
  static const char *__automount_attrs[ATTRTAB_SIZE + 1];

  (*automount_attrs) = __automount_attrs;

  (*automount_attrs)[0] = AT (automountKey);
  (*automount_attrs)[1] = AT (automountInformation);
  (*automount_attrs)[2] = ATM (LM_AUTOMOUNT, description);
  (*automount_attrs)[3] = NULL;
}

