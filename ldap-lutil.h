/* $OpenLDAP$ */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE.OpenLDAP in the
 * top-level directory of the distribution.
 */

#ifndef _LUTIL_LDAP_H
#define _LUTIL_LDAP_H 1

#include <ldap_cdefs.h>
#include <lber_types.h>

/*
 * Include file for lutil LDAP routines
 */

void *_nss_ldap_sasl_defaults(
	LDAP *ld,
	char *mech,
	char *realm,
	char *authcid,
	char *passwd,
	char *authzid);

int _nss_ldap_sasl_interact(
	LDAP *ld, unsigned flags, void *defaults, void *p);

#endif /* _LUTIL_LDAP_H */
