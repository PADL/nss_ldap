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

#if !defined(IRS_NSS)

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

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ldap-nss.h"
#include "ldap-bp.h"
#include "globals.h"
#include "util.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_key_t bp_context = NULL;
#elif defined(SUN_NSS)
static context_key_t bp_context = { 0 };
#endif

PARSER _nss_ldap_parse_bp(
	LDAP *ld,
	LDAPMessage *e,
	ldap_state_t *pvt,
	void *result,
	char *buffer,
	size_t buflen)
{
	struct bootparams *bp = (struct bootparams *)result;
	NSS_STATUS stat;

	stat = _nss_ldap_getdomainname(ld, e, &bp->bp_name, &buffer, &buflen);
	if (stat != NSS_SUCCESS) return stat;

	stat = _nss_ldap_assign_attrvals(ld, e, LDAP_ATTR_BOOTPARAM, NULL, &bp->bp_params, &buffer, &buflen, NULL);
	if (stat != NSS_SUCCESS) return stat;

	return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_getbootparamsbyname_r(nss_backend_t *be, void *args)
{
	LOOKUP_NAME(args, filt_getbootparamsbyname, bp_attributes, _nss_ldap_parse_bp);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS _nss_ldap_bootparams_destr(nss_backend_t *be, void *args)
{
	_nss_ldap_default_destr(&bp_context);
	return NSS_SUCCESS;
}

static nss_backend_op_t bp_ops[] =
{
	_nss_ldap_bootparams_destr,
	_nss_ldap_getbootparamsbyname_r
};

nss_backend_t *_nss_ldap_bootparams_constr(const char *db_name,
	const char *src_name,
	const char *cfg_args)
{
	static nss_backend_t be;

	/* until we figure this out, this is deliberately broken. */

	return NULL;

/*
	be.ops = bp_ops;
	be.n_ops = sizeof(bp_ops) / sizeof(nss_backend_op_t);

	if (_nss_ldap_default_constr(&bp_context) != NSS_SUCCESS)
		return NULL;

	return &be;
 */
}

#endif /* !GNU_NSS */

#endif /* !IRS_NSS */
