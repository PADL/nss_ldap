/* Copyright (C) 1999 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 1999.

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

#ifndef _LDAP_NSS_LDAP_LDAP_SCHEMA_H
#define _LDAP_NSS_LDAP_LDAP_SCHEMA_H

/**
 * These could potentially be replaced with
 * lookup macros.
 */
#define OC(oc)                    OC##_##oc
#define AT(at)                    AT##_##at

/**
 * Common attributes, not from RFC 2307.
 */
#define AT_objectClass            "objectClass"
#define AT_cn                     "cn"
#define AT_uid                    "uid"
#define AT_description            "description"
#define AT_member                 "member"
#define AT_uniqueMember           "uniqueMember"
#define AT_l                      "l"
#define AT_manager                "manager"

/**
 * Vendor-specific attributes and object classes.
 * (Mainly from Sun.)
 */
#define OC_nisMailAlias	          "nisMailAlias"
#define AT_rfc822MailMember       "rfc822MailMember"

/**
 * RFC 2307 attributes and object classes.
 */

/*
 * ( nisSchema.2.0 NAME 'posixAccount' SUP top AUXILIARY
 *   DESC 'Abstraction of an account with POSIX attributes'
 *   MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
 *   MAY ( userPassword $ loginShell $ gecos $ description ) )
 */
#define OC_posixAccount           "posixAccount"
#define AT_userPassword           "userPassword"
#define AT_uidNumber              "uidNumber"
#define AT_gidNumber              "gidNumber"
#define AT_homeDirectory          "homeDirectory"
#define AT_loginShell             "loginShell"
#define AT_gecos                  "gecos"

/*
 * ( nisSchema.2.1 NAME 'shadowAccount' SUP top AUXILIARY
 *   DESC 'Additional attributes for shadow passwords'            
 *   MUST uid
 *   MAY ( userPassword $ shadowLastChange $ shadowMin
 *         shadowMax $ shadowWarning $ shadowInactive $
 *         shadowExpire $ shadowFlag $ description ) )
 */
#define OC_shadowAccount          "shadowAccount"
#define AT_shadowLastChange       "shadowLastChange"
#define AT_shadowMin              "shadowMin"
#define AT_shadowMax              "shadowMax"
#define AT_shadowWarning          "shadowWarning"
#define AT_shadowInactive         "shadowInactive"
#define AT_shadowExpire           "shadowExpire"
#define AT_shadowFlag             "shadowFlag"

/*
 * ( nisSchema.2.2 NAME 'posixGroup' SUP top STRUCTURAL            
 *   DESC 'Abstraction of a group of accounts'
 *   MUST ( cn $ gidNumber )
 *   MAY ( userPassword $ uidMember $ description ) )
 */
#define OC_posixGroup             "posixGroup"
#define AT_gidNumber              "gidNumber"
#define AT_memberUid              "memberUid"

/*
 * ( nisSchema.2.3 NAME 'ipService' SUP top STRUCTURAL
 *   DESC 'Abstraction an Internet Protocol service.
 *         Maps an IP port and protocol (such as tcp or udp)
 *         to one or more names; the distinguished value of
 *         the cn attribute denotes the service's canonical
 *         name'
 *   MUST ( cn $ ipServicePort $ ipServiceProtocol )
 *   MAY ( description ) )
 */
#define OC_ipService              "ipService"
#define AT_ipServicePort          "ipServicePort"
#define AT_ipServiceProtocol      "ipServiceProtocol"

/*
 * ( nisSchema.2.4 NAME 'ipProtocol' SUP top STRUCTURAL
 *   DESC 'Abstraction of an IP protocol. Maps a protocol number
 *         to one or more names. The distinguished value of the cn
 *         attribute denotes the protocol's canonical name'
 *   MUST ( cn $ ipProtocolNumber )
 *    MAY description )
 */
#define OC_ipProtocol             "ipProtocol"
#define AT_ipProtocolNumber       "ipProtocolNumber"

/*
 * ( nisSchema.2.5 NAME 'oncRpc' SUP top STRUCTURAL
 *   DESC 'Abstraction of an Open Network Computing (ONC)
 *         [RFC1057] Remote Procedure Call (RPC) binding.
 *         This class maps an ONC RPC number to a name.
 *         The distinguished value of the cn attribute denotes
 *         the RPC service's canonical name'
 *   MUST ( cn $ oncRpcNumber )
 *   MAY description )
 */
#define OC_oncRpc                 "oncRpc"
#define AT_oncRpcNumber           "oncRpcNumber"

/*
 * ( nisSchema.2.6 NAME 'ipHost' SUP top AUXILIARY
 *   DESC 'Abstraction of a host, an IP device. The distinguished
 *         value of the cn attribute denotes the host's canonical
 *         name. Device SHOULD be used as a structural class'
 *   MUST ( cn $ ipHostNumber )
 *   MAY ( l $ description $ manager ) ) 
 */
#define OC_ipHost                 "ipHost"
#define AT_ipHostNumber           "ipHostNumber"

/*
 * ( nisSchema.2.7 NAME 'ipNetwork' SUP top STRUCTURAL
 *   DESC 'Abstraction of a network. The distinguished value of
 *   MUST ( cn $ ipNetworkNumber )
 *   MAY ( ipNetmaskNumber $ l $ description $ manager ) )
 */
#define OC_ipNetwork              "ipNetwork"
#define AT_ipNetworkNumber        "ipNetworkNumber"
#define AT_ipNetmaskNumber        "ipNetmaskNumber"

/*
 * ( nisSchema.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
 *   DESC 'Abstraction of a netgroup. May refer to other netgroups'
 *   MUST cn
 *   MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
 */
#define OC_nisNetgroup            "nisNetgroup"
#define AT_nisNetgroupTriple      "nisNetgroupTriple"
#define AT_memberNisNetgroup      "memberNisNetgroup"

/*
 * ( nisSchema.2.09 NAME 'nisMap' SUP top STRUCTURAL
 *   DESC 'A generic abstraction of a NIS map'
 *   MUST nisMapName
 *   MAY description )
 */
#define OC_nisMap                 "nisMap"
#define AT_nisMapName             "nisNapName"

/*
 * ( nisSchema.2.10 NAME 'nisObject' SUP top STRUCTURAL
 *   DESC 'An entry in a NIS map'
 *   MUST ( cn $ nisMapEntry $ nisMapName )
 *   MAY description )
 */
#define OC_nisObject              "nisObject"
#define AT_nisMapEntry            "nisMapEntry"

/*
 * ( nisSchema.2.11 NAME 'ieee802Device' SUP top AUXILIARY
 *   DESC 'A device with a MAC address; device SHOULD be
 *         used as a structural class'
 *   MAY macAddress )
 */
#define OC_ieee802Device          "ieee802Device"
#define AT_macAddress             "macAddress"

/*
 * ( nisSchema.2.12 NAME 'bootableDevice' SUP top AUXILIARY
 *   DESC 'A device with boot parameters; device SHOULD be
 *         used as a structural class'
 *   MAY ( bootFile $ bootParameter ) )
 */
#define OC_bootableDevice         "bootableDevice"
#define AT_bootFile               "bootFile"
#define AT_bootParameter          "bootParameter"

#endif /* _LDAP_NSS_LDAP_LDAP_SCHEMA_H */
