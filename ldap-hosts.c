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


static char rcsId[] = "$Id$";

#ifdef IRS_NSS
#include <port_before.h>
#endif

#ifdef SUN_NSS
#include <thread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <lber.h>
#include <ldap.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>

#ifdef GNU_NSS
#include <nss.h>
#ifdef INET6
# include <resolv/mapv4v6addr.h>
# include <resolv/mapv4v6hostent.h>
#endif
/* XXX bogus ? */
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#ifndef MAXALIASES
#define MAXALIASES 35
#endif

#include "ldap-nss.h"
#include "ldap-hosts.h"
#include "globals.h"
#include "util.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_key_t hosts_context = NULL;
#elif defined(SUN_NSS)
static context_key_t hosts_context = { 0 };
#endif

PARSER _nss_ldap_parse_host(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen)
{
	/* this code needs reviewing. XXX */
	struct hostent *host = (struct hostent *)result;
	NSS_STATUS stat;
#ifdef INET6
	char addressbuf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") * MAXALIASES];
#else
	char addressbuf[sizeof("255.255.255.255") * MAXALIASES];
#endif
	char *p_addressbuf = addressbuf;
	char **addresses = NULL;
	size_t addresslen = sizeof(addressbuf);
	size_t addresscount = 0;
	char **host_addresses = NULL;
	int i;

	*addressbuf = *buffer = '\0';
	
	stat = _nss_ldap_getdomainname(ld, e, &host->h_name, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	stat = _nss_ldap_assign_attrvals(ld, e, LDAP_ATTR_HOSTNAME, host->h_name, &host->h_aliases,
		&buffer, &buflen, NULL);
	if (stat != NSS_SUCCESS)
		return stat;

	stat = _nss_ldap_assign_attrvals(ld, e, LDAP_ATTR_HOSTADDR, NULL, &addresses,
		&p_addressbuf, &addresslen, &addresscount);
	if (stat != NSS_SUCCESS)
		return stat;
	if (addresscount == 0)
		return NSS_NOTFOUND;

#ifdef INET6
	if (_res.options & RES_USE_INET6)
		{
		if (bytesleft(buffer, buflen) < (size_t)((addresscount + 1) * IN6ADDRSZ))
			return NSS_TRYAGAIN;
		}
	else
		{
		if (bytesleft(buffer, buflen) < (size_t)((addresscount + 1) * INADDRSZ))
			return NSS_TRYAGAIN;
		}
#else
	if (bytesleft(buffer, buflen) < (size_t)((addresscount + 1) * INADDRSZ))
		return NSS_TRYAGAIN;
#endif

	align(buffer);
	host_addresses = (char **)buffer;
	host->h_addr_list = host_addresses;
	host_addresses[addresscount] = NULL;

#ifdef INET6
	if (_res.options & RES_USE_INET6)
		{
		buffer += (addresscount + 1) * IN6ADDRSZ;
		buflen -= (addresscount + 1) * IN6ADDRSZ;
	else
		{
		buffer += (addresscount + 1) * INADDRSZ;
		buflen -= (addresscount + 1) * INADDRSZ;
		}
#else
	buffer += (addresscount + 1) * INADDRSZ;
	buflen -= (addresscount + 1) * INADDRSZ;
	host->h_addrtype = AF_INET;
	host->h_length = INADDRSZ;
#endif

	for (i = 0; i < (int)addresscount; i++)
		{
#ifdef INET6
		char *addr = addresses[i];
		char entdata[16];
		/* from glibc NIS parser. Thanks, Uli. */

		if ((_res.options & RES_USE_INET6) &&
			inet_pton(AF_INET6, curaddress, entdata) > 0)
			{
			if (i == 0)
				{
				host->h_addrtype = AF_INET6;
				host->h_length = IN6ADDRSZ;
				}
			}
		else
			{
			if (inet_pton(AF_INET, addr, entdata) > 0)
				{
				if (_res.options & RES_USE_INET6)
					{
					map_v4v6_address((char *)entdata, (char *)entdata);
					if (i == 0)
						{
						host->h_addrtype = AF_INET6;
						host->h_length = IN6ADDRSZ;
						}
					}
				else
					{
					if (i == 0)
						{
						host->h_addrtype = AF_INET;
						host->h_length = INADDRSZ;
						}
					}
				}
			}
#else
		unsigned long haddr;
/*		debug(addresses[i]); */
		haddr = inet_addr(addresses[i]);
#endif

		if (buflen < (size_t)host->h_length)
			return NSS_TRYAGAIN;

#ifdef INET6
		memcpy(buffer, entdata, host->h_length);
		*host_addresses = buffer;
		buffer += host->h_length;
		buflen -= host->h_length;
#else
		memcpy(buffer, &haddr, INADDRSZ);
		*host_addresses = buffer;
		buffer += INADDRSZ;
		buflen -= INADDRSZ;
#endif

		host_addresses++;
		}

#ifdef INET6
		/* If we need the host entry in IPv6 form change it now.  */
		if (_res.options & RES_USE_INET6)
			{
			map_v4v6_hostent (host, &buffer, &buflen);
			}
#endif

	return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_gethostbyname_r(nss_backend_t *be, void *args)
{
	ldap_args_t a;

	LA_INIT(a);
	LA_STRING(a) = NSS_ARGS(args)->key.name;
	LA_TYPE(a) = LA_TYPE_STRING;

	NSS_ARGS(args)->status = _nss_ldap_getbyname(&a,
		NSS_ARGS(args)->buf.result,
		NSS_ARGS(args)->buf.buffer,
		NSS_ARGS(args)->buf.buflen,
		filt_gethostbyname,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	NSS_ARGS(args)->returnval = (NSS_ARGS(args)->status == NSS_SUCCESS) ?
		NSS_ARGS(args)->buf.result : NULL;

	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);

	return NSS_ARGS(args)->status;
}
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_gethostbyname_r(const char *name, struct hostent *result,
				char *buffer, size_t buflen, int *h_errnop)
{
	NSS_STATUS status;
	ldap_args_t a;

	LA_INIT(a);
	LA_STRING(a) = name;
	LA_TYPE(a) = LA_TYPE_STRING;

	status = _nss_ldap_getbyname(&a,
		result,
		buffer,
		buflen,
		filt_gethostbyname,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	MAP_H_ERRNO(status, *h_errnop);

	return status;
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_gethostbyaddr_r(nss_backend_t *be, void *args)
{
	struct in_addr iaddr;
	ldap_args_t a;

	memcpy(&iaddr.s_addr, NSS_ARGS(args)->key.hostaddr.addr, NSS_ARGS(args)->key.hostaddr.len);
	LA_INIT(a);
	LA_STRING(a) = inet_ntoa(iaddr);
	LA_TYPE(a) = LA_TYPE_STRING;

	NSS_ARGS(args)->status = _nss_ldap_getbyname(&a,
		NSS_ARGS(args)->buf.result,
		NSS_ARGS(args)->buf.buffer,
		NSS_ARGS(args)->buf.buflen,
		filt_gethostbyaddr,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	NSS_ARGS(args)->returnval = (NSS_ARGS(args)->status == NSS_SUCCESS) ?
		NSS_ARGS(args)->buf.result : NULL;

	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);

	return NSS_ARGS(args)->status;
}
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_gethostbyaddr_r(int number, struct hostent *result,
				char *buffer, size_t buflen, int *h_errnop)
{
	NSS_STATUS status;
	ldap_args_t a;
	struct in_addr iaddr;

	/* if querying by IPv6 address, make sure the address is "normalized" --
	 * it should contain no leading zeros and all components of the address.
	 * still we can't fit an IPv6 address in an int, so who cares for now.
	 */

	LA_INIT(a);
	LA_STRING(a) = inet_ntoa(iaddr);
	LA_TYPE(a) = LA_TYPE_STRING;

	status = _nss_ldap_getbyname(&a,
		result,
		buffer,
		buflen,
		filt_gethostbyaddr,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	MAP_H_ERRNO(status, *h_errnop);

	return status;
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_sethostent_r(nss_backend_t *be, void *fakeargs)
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_sethostent_r(void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_SETENT(hosts_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_endhostent_r(nss_backend_t *be, void *fakeargs)
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_endhostent_r(void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_ENDENT(hosts_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_gethostent_r(nss_backend_t *be, void *args)
{
	NSS_ARGS(args)->status = _nss_ldap_getent(
		hosts_context,
		NSS_ARGS(args)->buf.result,
		NSS_ARGS(args)->buf.buffer,
		NSS_ARGS(args)->buf.buflen,
		filt_gethostent,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	NSS_ARGS(args)->returnval = (NSS_ARGS(args)->status == NSS_SUCCESS) ?
		NSS_ARGS(args)->buf.result : NULL;

	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);

	return NSS_ARGS(args)->status;
}
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_gethostent_r(struct hostent *result, char *buffer, size_t buflen, int *h_errnop)
{
	NSS_STATUS status;

	status = _nss_ldap_getent(
		hosts_context,
		result,
		buffer,
		buflen,
		filt_gethostent,
		(const char **)host_attributes,
		_nss_ldap_parse_host);

	MAP_H_ERRNO(status, *h_errnop);

	return status;
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_hosts_destr(nss_backend_t *be, void *args)
{
	_nss_ldap_default_destr(&hosts_context);
	return NSS_SUCCESS;
}

static nss_backend_op_t hosts_ops[] =
{
	_nss_ldap_hosts_destr,
	_nss_ldap_endhostent_r,
	_nss_ldap_sethostent_r,
	_nss_ldap_gethostent_r,
	_nss_ldap_gethostbyname_r,
	_nss_ldap_gethostbyaddr_r
};

nss_backend_t *_nss_ldap_hosts_constr(const char *db_name,
	const char *src_name,
	const char *cfg_args)
{
	static nss_backend_t be;

	be.ops = hosts_ops;
	be.n_ops = sizeof(hosts_ops) / sizeof(nss_backend_op_t);

	if (_nss_ldap_default_constr(&hosts_context) != NSS_SUCCESS)
		return NULL;

	return &be;
}

#endif /* !GNU_NSS */

#ifdef IRS_NSS
#include "irs-hosts.c"
#endif

