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

/* parts based on nss_nis */

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
#include <sys/socket.h>
#include <errno.h>

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#include "ldap-nss.h"
#include "ldap-network.h"
#include "globals.h"
#include "util.h"

#ifdef IRS_NSS
#include <irs.h>
#include <port_after.h>

#define MAXALIASES 35
#define MAXADDRSIZE 4

#endif


#ifdef GNU_NSS
static context_key_t net_context = NULL;
#elif defined(SUN_NSS)
static context_key_t net_context = { 0 };
#endif

PARSER _nss_ldap_parse_net(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen)
{

	char *tmp;
#ifdef IRS_NSS
	struct nwent *network = (struct nwent *)result;
	unsigned char *addr;
#else
	struct netent *network = (struct netent *)result;
#endif
	NSS_STATUS stat;

	/* IPv6 support ? XXX */
	network->n_addrtype = AF_INET;

	stat = _nss_ldap_getdomainname(ld, e, &network->n_name, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	stat = _nss_ldap_assign_attrval(ld, e, LDAP_ATTR_NETWORKADDR, &tmp, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;
#ifdef IRS_NSS
	if (buflen < MAXADDRSIZE)
		return NSS_TRYAGAIN;
	addr = buffer;
	buffer += MAXADDRSIZE;
	buffer -= MAXADDRSIZE;
	network->n_length = inet_net_pton(AF_INET, tmp, &addr, MAXADDRSIZE);
	network->n_addr = addr;
#else
	network->n_net = inet_network(tmp);
#endif

	stat = _nss_ldap_assign_attrvals(ld, e, LDAP_ATTR_NETWORKNAME, network->n_name, &network->n_aliases,
		&buffer, &buflen, NULL);
	if (stat != NSS_SUCCESS) return stat;

	return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getnetbyname_r(nss_backend_t *be, void *args)
{
	ldap_args_t a;

	LA_INIT(a);
	LA_STRING(a) = NSS_ARGS(args)->key.name;
	LA_TYPE(a) = LA_TYPE_STRING;

	NSS_ARGS(args)->status = _nss_ldap_getbyname(&a,
		NSS_ARGS(args)->buf.result,
		NSS_ARGS(args)->buf.buffer,
		NSS_ARGS(args)->buf.buflen,
		filt_getnetbyname,
		(const char **)net_attributes,
		_nss_ldap_parse_net);

	NSS_ARGS(args)->returnval = (NSS_ARGS(args)->status == NSS_SUCCESS) ? 
		NSS_ARGS(args)->buf.result : NULL;
	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);

	return NSS_ARGS(args)->status;
}
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_getnetbyname_r(const char *name, struct netent *result,
				char *buffer, size_t buflen, int *herrnop)
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
		filt_getnetbyname,
		(const char **)net_attributes,
		_nss_ldap_parse_net);

	MAP_H_ERRNO(status, *herrnop);

	return status;
}
#endif

#if defined(GNU_NSS) || defined(SUN_NSS)
#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getnetbyaddr_r(nss_backend_t *be, void *args)
#else
NSS_STATUS _nss_ldap_getnetbyaddr_r(unsigned long addr, int type, struct netent *result,
				char *buffer, size_t buflen, int *herrnop)
#endif
{
	struct in_addr in;
	char buf[256];
	int blen;
	ldap_args_t a;

	LA_INIT(a);
	LA_TYPE(a) = LA_TYPE_STRING;
	LA_STRING(a) = buf;
	/* we can keep the session open for all our queries here */
	LA_STAYOPEN(a) = 1;

#ifdef SUN_NSS
	in = inet_makeaddr(NSS_ARGS(args)->key.netaddr.net, 0);
#else
	in = inet_makeaddr(addr, 0);
#endif
	strcpy(buf, inet_ntoa(in));
	blen = strlen(buf);

	while (1)
		{
		NSS_STATUS retval;
#ifdef SUN_NSS
		retval = _nss_ldap_getbyname(&a, NSS_ARGS(args)->buf.result, NSS_ARGS(args)->buf.buffer,
			 NSS_ARGS(args)->buf.buflen,
#else
		retval = _nss_ldap_getbyname(&a, result, buffer, buflen,
#endif
			filt_getnetbyaddr, (const char **)net_attributes, _nss_ldap_parse_net);

		if (retval != NSS_SUCCESS)
			{
			if (retval == NSS_NOTFOUND)
				{
				if (buf[blen - 2] == '.' && buf[blen - 1] == '\0')
					{
					buf[blen - 2] = '\0';
					blen -= 2;
					continue;
					}
				else
					{
#ifdef SUN_NSS
					NSS_ARGS(args)->returnval = NULL;
					NSS_ARGS(args)->status = retval;
					MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);
#else
					MAP_H_ERRNO(NSS_NOTFOUND, *herrnop);
#endif
					LA_CLOSE(a);
					return NSS_NOTFOUND;
					}
				}
			else
				{
#ifndef SUN_NSS
				if (retval == NSS_TRYAGAIN)
					{
					__set_errno(EAGAIN);
					}
					MAP_H_ERRNO(retval, *herrnop);
#else
					NSS_ARGS(args)->returnval = NULL;
					NSS_ARGS(args)->status = retval;
					MAP_H_ERRNO(retval, NSS_ARGS(args)->status);
#endif
					LA_CLOSE(a);
					return retval;
				}
			}
		}
#ifdef SUN_NSS
	NSS_ARGS(args)->returnval = NSS_ARGS(args)->buf.result;
	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);
#else
	MAP_H_ERRNO(NSS_SUCCESS, *herrnop);
#endif
	LA_CLOSE(a);
	return NSS_SUCCESS;
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_setnetent_r(nss_backend_t *be, void *fakeargs)
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_setnetent_r(void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_SETENT(net_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_endnetent_r(nss_backend_t *be, void *fakeargs)
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_endnetent_r(void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
	LOOKUP_ENDENT(net_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getnetent_r(nss_backend_t *be, void *args)
{
	NSS_ARGS(args)->status = _nss_ldap_getent(
		net_context,
		NSS_ARGS(args)->buf.result,
		NSS_ARGS(args)->buf.buffer,
		NSS_ARGS(args)->buf.buflen,
		filt_getnetent,
		(const char **)net_attributes,
		_nss_ldap_parse_net);

	NSS_ARGS(args)->returnval = (NSS_ARGS(args)->status == NSS_SUCCESS) ?
		NSS_ARGS(args)->buf.result : NULL;
	MAP_H_ERRNO(NSS_ARGS(args)->status, NSS_ARGS(args)->h_errno);

	return NSS_ARGS(args)->status;
}
#elif defined(GNU_NSS)
NSS_STATUS _nss_ldap_getnetent_r(struct netent *result, char *buffer, size_t buflen, int *herrnop)
{
	NSS_STATUS status;

	status = _nss_ldap_getent(
		net_context,
		result,
		buffer,
		buflen,
		filt_getnetent,
		(const char **)net_attributes,
		_nss_ldap_parse_net);

	MAP_H_ERRNO(status, *herrnop);

	return status;
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_networks_destr(nss_backend_t *be, void *args)
{
	_nss_ldap_default_destr(&net_context);
	return NSS_SUCCESS;
}

static nss_backend_op_t networks_ops[] =
{
	_nss_ldap_networks_destr,
	_nss_ldap_endnetent_r,
	_nss_ldap_setnetent_r,
	_nss_ldap_getnetent_r,
	_nss_ldap_getnetbyname_r,
	_nss_ldap_getnetbyaddr_r
};

nss_backend_t *_nss_ldap_networks_constr(const char *db_name,
	const char *src_name,
	const char *cfg_args)
{
	static nss_backend_t be;

	be.ops = networks_ops;
	be.n_ops = sizeof(networks_ops) / sizeof(nss_backend_op_t);

	if (_nss_ldap_default_constr(&net_context) != NSS_SUCCESS)
		return NULL;

	return &be;
}

#endif /* !GNU_NSS */

#ifdef IRS_NSS
#include "irs-network.c"
#endif

