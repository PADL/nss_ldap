
/* Copyright (C) 1997 Luke Howard.
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


#ifndef _LDAP_NSS_LDAP_LDAP_PARSE_H
#define _LDAP_NSS_LDAP_LDAP_PARSE_H

#if defined(SUN_NSS)
#define NSS_ARGS(args)	((nss_XbyY_args_t *)args)

#define LOOKUP_NAME(args, filter, attributes, parser) \
	ldap_args_t a; \
	NSS_STATUS s; \
	LA_INIT(a); \
	LA_STRING(a) = NSS_ARGS(args)->key.name; \
	LA_TYPE(a) = LA_TYPE_STRING; \
	s = _nss_ldap_getbyname(&a, \
		NSS_ARGS(args)->buf.result, \
		NSS_ARGS(args)->buf.buffer, \
		NSS_ARGS(args)->buf.buflen, \
		&NSS_ARGS(args)->erange, \
		filter, \
		(const char **)attributes, \
		parser); \
	if (s == NSS_SUCCESS) { \
		NSS_ARGS(args)->returnval = NSS_ARGS(args)->buf.result; \
	} \
	return s
#define LOOKUP_NUMBER(args, field, filter, attributes, parser) \
	ldap_args_t a; \
	NSS_STATUS s; \
	LA_INIT(a); \
	LA_NUMBER(a) = NSS_ARGS(args)->field; \
	LA_TYPE(a) = LA_TYPE_NUMBER; \
	s = _nss_ldap_getbyname(&a, \
		NSS_ARGS(args)->buf.result, \
		NSS_ARGS(args)->buf.buffer, \
		NSS_ARGS(args)->buf.buflen, \
		&NSS_ARGS(args)->erange, \
		filter, \
		(const char **)attributes, \
		parser); \
	if (s == NSS_SUCCESS) { \
		NSS_ARGS(args)->returnval = NSS_ARGS(args)->buf.result; \
	} \
	return s
#define LOOKUP_GETENT(args, be, filter, attributes, parser) \
	NSS_STATUS s; \
	s = _nss_ldap_getent(&((nss_ldap_backend_t *)be)->state, \
		NSS_ARGS(args)->buf.result, \
		NSS_ARGS(args)->buf.buffer, \
		NSS_ARGS(args)->buf.buflen, \
		&NSS_ARGS(args)->erange, \
		filter, \
		(const char **)attributes, \
		parser); \
	if (s == NSS_SUCCESS) { \
		NSS_ARGS(args)->returnval = NSS_ARGS(args)->buf.result; \
	} \
	return s

#elif defined(GNU_NSS)

#define LOOKUP_NAME(name, result, buffer, buflen, errnop, filter, attributes, parser) \
	ldap_args_t a; \
	LA_INIT(a); \
	LA_STRING(a) = name; \
	LA_TYPE(a) = LA_TYPE_STRING; \
	return _nss_ldap_getbyname(&a, result, buffer, buflen, errnop, filter, (const char **)attributes, parser);
#define LOOKUP_NUMBER(number, result, buffer, buflen, errnop, filter, attributes, parser) \
	ldap_args_t a; \
	LA_INIT(a); \
	LA_NUMBER(a) = number; \
	LA_TYPE(a) = LA_TYPE_NUMBER; \
	return _nss_ldap_getbyname(&a, result, buffer, buflen, errnop, filter, (const char **)attributes, parser)
#define LOOKUP_GETENT(key, result, buffer, buflen, errnop, filter, attributes, parser) \
	return _nss_ldap_getent(&key, result, buffer, buflen, errnop, filter, (const char **)attributes, parser)

#elif defined(IRS_NSS)

#define LOOKUP_NAME(name, this, filter, attributes, parser) \
	ldap_args_t a; \
	struct pvt *pvt = (struct pvt *)this->private; \
	NSS_STATUS s; \
	LA_INIT(a); \
	LA_STRING(a) = name; \
	LA_TYPE(a) = LA_TYPE_STRING; \
	s = _nss_ldap_getbyname(&a, &pvt->result, pvt->buffer, sizeof(pvt->buffer), &errno, filter, \
		(const char **)attributes, parser); \
	if (s != NSS_SUCCESS) { \
		MAP_ERRNO(s, errno); \
		return NULL; \
	} \
	return &pvt->result;
#define LOOKUP_NUMBER(number, this, filter, attributes, parser) \
	ldap_args_t a; \
	struct pvt *pvt = (struct pvt *)this->private; \
	NSS_STATUS s; \
	LA_INIT(a); \
	LA_NUMBER(a) = number; \
	LA_TYPE(a) = LA_TYPE_NUMBER; \
	s = _nss_ldap_getbyname(&a, &pvt->result, pvt->buffer, sizeof(pvt->buffer), &errno, filter, \
		(const char **)attributes, parser); \
	if (s != NSS_SUCCESS) { \
		MAP_ERRNO(s, errno); \
		return NULL; \
	} \
	return &pvt->result;
#define LOOKUP_GETENT(this, filter, attributes, parser) \
	struct pvt *pvt = (struct pvt *)this->private; \
	NSS_STATUS s; \
	s = _nss_ldap_getent(&pvt->state, &pvt->result, pvt->buffer, \
		sizeof(pvt->buffer), &errno, filter, \
		(const char **)attributes, parser); \
	if (s != NSS_SUCCESS) { \
		MAP_ERRNO(s, errno); \
		return NULL; \
	} \
	return &pvt->result;
#endif

#if defined(IRS_NSS)

#define LOOKUP_SETENT(this) \
	struct pvt *pvt = (struct pvt *)this->private; \
	(void) _nss_ldap_ent_context_init(&pvt->state)
#define LOOKUP_ENDENT(this) \
	struct pvt *pvt = (struct pvt *)this->private; \
	nss_lock(); \
	_nss_ldap_ent_context_zero(pvt->state); \
	nss_unlock();

#elif defined(SUN_NSS)

#define LOOKUP_SETENT(key) \
	if (_nss_ldap_ent_context_init(&((nss_ldap_backend_t *)key)->state) == NULL) \
		return NSS_UNAVAIL; \
	return NSS_SUCCESS
#define LOOKUP_ENDENT(key) \
	nss_lock(); \
	_nss_ldap_ent_context_zero(((nss_ldap_backend_t *)key)->state); \
	nss_unlock(); \
	return NSS_SUCCESS

#else

#define LOOKUP_SETENT(key) \
	if (_nss_ldap_ent_context_init(&key) == NULL) \
		return NSS_UNAVAIL; \
	return NSS_SUCCESS
#define LOOKUP_ENDENT(key) \
	nss_lock(); \
	_nss_ldap_ent_context_zero(key); \
	nss_unlock(); \
	return NSS_SUCCESS
#endif

#endif /* _LDAP_NSS_LDAP_LDAP_PARSE_H */
