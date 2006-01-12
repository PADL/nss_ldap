/* Copyright (C) 1997-2006 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2006.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <assert.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#include <net/if.h>
#include <netinet/in.h>

#include "ldap-nss.h"
#include "ldap-automount.h"
#include "ldap-sldap.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSSWITCH_H

/*
 * This implements enough of the Solaris libsldap interface in order
 * for the automounter to work.
 */

static ns_ldap_return_code __ns_ldap_initResult(ns_ldap_result_t **presult);

static void **
__ns_ldap_makeStringParam(const char *string)
{
	void **p;

	p = (void **)malloc(2 * sizeof(void *));
	if (p == NULL) {
		return NULL;
	}
	p[0] = strdup(string);
	if (p[0] == NULL) {
		free(p);
		return NULL;
	}
	p[1] = NULL;

	return p;
}

char **
__ns_ldap_getMappedAttributes(const char *service, const char *attribute)
{
	const char *mapped;

	mapped = _nss_ldap_map_at(_nss_ldap_str2selector(service), attribute);
	if (mapped == NULL) {
		return NULL;
	}

	return (char **)__ns_ldap_makeStringParam(mapped);
}

char **
__ns_ldap_getMappedObjectClass(const char *service, const char *objectClass)
{
	const char *mapped;

	mapped = _nss_ldap_map_oc(objectClass);
	if (mapped == NULL) {
		return NULL;
	}

	return (char **)__ns_ldap_makeStringParam(mapped);
}

static ns_ldap_return_code
__ns_ldap_mapError(NSS_STATUS error)
{
	ns_ldap_return_code code;

	switch (error) {
	case NSS_SUCCESS:
		code = NS_LDAP_SUCCESS;
		break;
	case NSS_TRYAGAIN:
		code = NS_LDAP_MEMORY;
		break;
	case NSS_NOTFOUND:
		code = NS_LDAP_NOTFOUND;
		break;
	case NSS_UNAVAIL:
	default:
		code = NS_LDAP_OP_FAILED;
		break;
	}

	return code;
}

static ns_ldap_return_code
__ns_ldap_mapErrorDetail(ns_ldap_return_code code, ns_ldap_error_t **errorp)
{
	char *m = NULL;
	char *s = NULL;

	*errorp = (ns_ldap_error_t *)calloc(1, sizeof(ns_ldap_error_t));
	if (*errorp == NULL) {
		return NS_LDAP_MEMORY;
	}

	(*errorp)->status = _nss_ldap_get_ld_errno(&m, &s);
	(*errorp)->message = (m != NULL) ? strdup(m) : NULL;

	return code;
}

ns_ldap_return_code
__ns_ldap_freeError(ns_ldap_error_t **errorp)
{
	if (errorp == NULL) {
		return NS_LDAP_INVALID_PARAM;
	}
	if (*errorp != NULL) {
		if ((*errorp)->message != NULL) {
			free((*errorp)->message);
			(*errorp)->message = NULL;
		}
		free(*errorp);
		*errorp = NULL;
	}
	return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeParam(void ***data)
{
	void **p;

	if (*data != NULL) {
		for (p = *data; *p != NULL; p++) {
			free(*p);
			*p = NULL;
		}
		free(*data);
		*data = NULL;
	}

	return NS_LDAP_SUCCESS;
}


ns_ldap_return_code
__ns_ldap_getParam(const ParamIndexType type, void ***data, ns_ldap_error_t **errorp)
{
	*errorp = NULL;

	switch (type) {
	case NS_LDAP_FILE_VERSION_P:
		*data = __ns_ldap_makeStringParam(NS_LDAP_VERSION);
		return NS_LDAP_SUCCESS;
	default:
	}
	return NS_LDAP_INVALID_PARAM;
}

ns_ldap_return_code
__ns_ldap_freeAttr(ns_ldap_attr_t **pattr)
{
	int i;
	ns_ldap_attr_t *attr = *pattr;

	if (attr != NULL) {
		if (attr->attrname != NULL) {
			free(attr->attrname);
		}
		if (attr->attrvalue != NULL) {
			for (i = 0; i < attr->value_count; i++) {
				free(attr->attrvalue[i]);
			}
			free(attr->attrvalue);
		}
	}

	return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeEntry(ns_ldap_entry_t **pentry)
{
	int i;
	ns_ldap_entry_t *entry = *pentry;

	if (entry != NULL) {
		if (entry->attr_pair != NULL) {
			for (i = 0; i < entry->attr_count; i++) {
				__ns_ldap_freeAttr(&entry->attr_pair[i]);
			}
			free(entry->attr_pair);
		}
		free(entry);
		*pentry = NULL;
	}

	return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_freeResult(ns_ldap_result_t **presult)
{
	ns_ldap_result_t *result;
	ns_ldap_entry_t *entry, *next = NULL;

	if (presult == NULL) {
		return NS_LDAP_INVALID_PARAM;
	}

	result = *presult;
	if (result == NULL) {
		return NS_LDAP_SUCCESS;
	}

	while (entry != NULL) {
		next = entry->next;
		__ns_ldap_freeEntry(&entry);
		entry = next;
	}

	free(result);
	*presult = NULL;

	return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_parseAttr(ns_ldap_cookie_t *cookie, LDAPMessage *entry, const char *attribute, ns_ldap_attr_t **pattr)
{
	ns_ldap_attr_t *attr;
	const char *unmappedAttribute;

	attr = (ns_ldap_attr_t *)malloc(sizeof(*attr));
	if (attr == NULL) {
		return NS_LDAP_MEMORY;
	}

	unmappedAttribute = _nss_ldap_unmap_at(cookie->sel, attribute);
	if (unmappedAttribute == NULL) {
		return NS_LDAP_INVALID_PARAM;
	}

	attr->attrname = strdup(unmappedAttribute);
	if (attr->attrname == NULL) {
		__ns_ldap_freeAttr(&attr);
		return NS_LDAP_MEMORY;
	}

	attr->attrvalue = _nss_ldap_get_values(entry, attr->attrname);
	attr->value_count = (attr->attrvalue != NULL) ? ldap_count_values(attr->attrvalue) : 0;

	*pattr = attr;

	return NS_LDAP_SUCCESS;
}

NSS_STATUS
__ns_ldap_parseEntry(LDAPMessage *msg, ldap_state_t *state,
	void *result, char *buffer, size_t buflen)
{
	ns_ldap_cookie_t *cookie = (ns_ldap_cookie_t *)result;
	char *attribute;
	BerElement *ber = NULL;
	ns_ldap_return_code ret = NS_LDAP_SUCCESS;
	ns_ldap_entry_t *entry;
	int attr_count = 0;

	entry = (ns_ldap_entry_t *)malloc(sizeof(*entry));
	if (entry == NULL) {
		cookie->ret = NS_LDAP_MEMORY;
		return NSS_NOTFOUND;
	}

	entry->attr_count = 0;
	entry->attr_pair = NULL;
	entry->next = NULL;

	for (attribute = _nss_ldap_first_attribute (msg, &ber);
		attribute != NULL;
		attribute = _nss_ldap_next_attribute (msg, ber)) {
		attr_count++;
#ifdef HAVE_LDAP_MEMFREE
		ldap_memfree(attribute);
#endif
	}

	if (ber != NULL)
		ber_free (ber, 0);

	entry->attr_pair = (ns_ldap_attr_t **)calloc(attr_count, sizeof(ns_ldap_attr_t *));
	if (entry->attr_pair == NULL) {
		__ns_ldap_freeEntry(&entry);
		cookie->ret = NS_LDAP_MEMORY;
		return NSS_NOTFOUND;
	}

	for (attribute = _nss_ldap_first_attribute (msg, &ber);
		attribute != NULL;
		attribute = _nss_ldap_next_attribute (msg, ber)) {
		ns_ldap_attr_t *attr;

		ret = __ns_ldap_parseAttr(cookie, msg, attribute, &attr);
#ifdef HAVE_LDAP_MEMFREE
		ldap_memfree(attribute);
#endif
		if (ret != NS_LDAP_SUCCESS) {
			continue;
		}
		entry->attr_pair[entry->attr_count++] = attr;
	}

	if (ber != NULL)
		ber_free (ber, 0);

	if (ret == NS_LDAP_SUCCESS) {
		if (cookie->result == NULL) {
			ret = __ns_ldap_initResult(&cookie->result);
			if (ret != NS_LDAP_SUCCESS) {
				__ns_ldap_freeEntry(&entry);
				return __ns_ldap_mapError(ret);
			}
			cookie->result->entry = entry;
		}

		entry->next = cookie->entry;
		cookie->entry = entry;

		if (cookie->callback != NULL) {
			cookie->cb_ret = (*cookie->callback)(entry, cookie->userdata);
		}

		cookie->result->entries_count++;
	} else {
		__ns_ldap_freeEntry(&entry);
	}

	return __ns_ldap_mapError(ret);
}

static ns_ldap_return_code
__ns_ldap_initResult(ns_ldap_result_t **presult)
{
	ns_ldap_result_t *result;

	result = (ns_ldap_result_t *)malloc(sizeof(ns_ldap_result_t));
	if (result == NULL) {
		return NS_LDAP_MEMORY;
	}

	result->entries_count = 0;
	result->entry = NULL;

	*presult = result;

	return NS_LDAP_SUCCESS;
}

static int
__ns_ldap_isAutomountMap(const char *map)
{
	return (strncmp(map, "auto_", 5) == 0);
}

static ldap_map_selector_t
__ns_ldap_str2selector(const char *map)
{
	ldap_map_selector_t sel = _nss_ldap_str2selector(map);

	if (sel == LM_NONE && __ns_ldap_isAutomountMap(map)) {
		sel = LM_AUTOMOUNT;
	}

	return sel;
}

static ns_ldap_return_code
__ns_ldap_mapAttributes(ns_ldap_cookie_t *cookie, const char ***pAttributes)
{
	const char **attributes;
	int i;

	*pAttributes = NULL;

	if (cookie->attribute == NULL) {
		return NS_LDAP_SUCCESS;
	}

	for (i = 0; cookie->attribute[i] != NULL; i++)
		;

	attributes = (const char **)calloc(i + 1, sizeof(char **));
	if (attributes == NULL) {
		return NS_LDAP_MEMORY;
	}

	for (i = 0; cookie->attribute[i] != NULL; i++) {
		attributes[i] = _nss_ldap_map_at(cookie->sel, cookie->attribute[i]);
		assert(attributes[i] != NULL);
	}
	attributes[i] = NULL;
	*pAttributes = attributes;

	return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_mapFilter(ns_ldap_cookie_t *cookie, char **pFilter)
{
	/* XXX this should actually do something ! */
	*pFilter = strdup(cookie->filter);
	if (*pFilter == NULL) {
		return NS_LDAP_MEMORY;
	}

	return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_freeCookie(ns_ldap_cookie_t **pCookie)
{
	ns_ldap_cookie_t *cookie;

	cookie = *pCookie;

	if (cookie != NULL) {
		if (cookie->map != NULL)
			free(cookie->map);
		if (cookie->filter != NULL)
			free(cookie->filter);
		if (cookie->attribute != NULL)
			ldap_value_free(cookie->attribute);
		if (cookie->state != NULL) {
			_nss_ldap_ent_context_release (cookie->state);
			free (cookie->state);
		}
		if (cookie->mapped_filter != NULL)
			free(cookie->mapped_filter);
		if (cookie->mapped_attribute != NULL)
			free(cookie->mapped_attribute);
		_nss_ldap_am_context_free(&cookie->am_state);
		__ns_ldap_freeResult(&cookie->result);
		free(cookie);
	}

	*pCookie = NULL;

	return NS_LDAP_SUCCESS;
}

static ns_ldap_return_code
__ns_ldap_initCookie(const char *map,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc, char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_cookie_t **pCookie,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata)
{
	ns_ldap_cookie_t *cookie;
	ns_ldap_return_code ret;
	size_t i;

	assert(pCookie != NULL && *pCookie == NULL);

	ret = __ns_ldap_mapError(_nss_ldap_init());
	if (ret != NS_LDAP_SUCCESS) {
		return ret;
	}

	cookie = (ns_ldap_cookie_t *)calloc(1, sizeof(*cookie));
	if (cookie == NULL) {
		return NS_LDAP_MEMORY;
	}

	if (map == NULL || filter == NULL) {
		__ns_ldap_freeCookie(&cookie);
		return NS_LDAP_INVALID_PARAM;
	}

	cookie->map = strdup(map);
	if (cookie->map == NULL) {
		__ns_ldap_freeCookie(&cookie);
		return NS_LDAP_MEMORY;
	}

	cookie->filter = strdup(filter);
	if (cookie->filter == NULL) {
		__ns_ldap_freeCookie(&cookie);
		return NS_LDAP_MEMORY;
	}

	if (attribute != NULL) {
		for (i = 0; attribute[i] != NULL; i++)
			;

		cookie->attribute = (char **)calloc(i + 1, sizeof(char *));
		if (cookie->attribute == NULL) {
			__ns_ldap_freeCookie(&cookie);
			return NS_LDAP_MEMORY;
		}

		for (i = 0; attribute[i] != NULL; i++) {
			cookie->attribute[i] = strdup(attribute[i]);
			if (cookie->attribute[i] == NULL) {
				__ns_ldap_freeCookie(&cookie);
				return NS_LDAP_MEMORY;
			}
		}	
		cookie->attribute[i] = NULL;
	}

	cookie->flags = flags;
	cookie->init_filter_cb = init_filter_cb;
	cookie->callback = callback;
	cookie->userdata = userdata;
	cookie->ret = -1;
	cookie->cb_ret = NS_LDAP_CB_NEXT;
	cookie->erange = 0;
	cookie->sel = __ns_ldap_str2selector(map);

	if (_nss_ldap_ent_context_init_locked(&cookie->state) == NULL) {
		__ns_ldap_freeCookie(&cookie);
		return NS_LDAP_INTERNAL;
	}

	cookie->result = NULL;
	cookie->entry = NULL;

	*pCookie = cookie;

	return NS_LDAP_SUCCESS;
}

/* caller acquires lock */
static ns_ldap_return_code
__ns_ldap_initSearch(ns_ldap_cookie_t *cookie)
{
	ns_ldap_return_code ret;
	NSS_STATUS stat;

	assert(cookie != NULL);
	assert(cookie->state != NULL);

	/*
	 * In the automount case, we need to do a search for a list of
	 * search bases
	 */
	if (cookie->sel == LM_AUTOMOUNT) {
		assert(cookie->am_state == NULL);

		stat = _nss_ldap_am_context_init(cookie->map, &cookie->am_state);
		if (stat != NSS_SUCCESS) {
			return __ns_ldap_mapError(stat);
		}
	}

	ret = __ns_ldap_mapAttributes(cookie, &cookie->mapped_attribute);
	if (ret != NS_LDAP_SUCCESS) {
		return ret;
	}

	ret = __ns_ldap_mapFilter(cookie, &cookie->mapped_filter);
	if (ret != NS_LDAP_SUCCESS) {
		return ret;
	}


	return ret;
}

/*
 * Performs a search given an existing cookie
 *
 * If cookie->result != NULL then the entry will be appended to
 * the result list. Use this for implementing __ns_ldap_list().
 *
 * If cookie->result == NULL then a new result list will be
 * allocated. Use thsi for implementing __ns_ldap_nextEntry().
 *
 * cookie->entry always points to the last entry in cookie->result
 * 
 * Caller should acquire global lock
 */
static ns_ldap_return_code
__ns_ldap_search(ns_ldap_cookie_t *cookie)
{
	ldap_args_t a;
	NSS_STATUS stat;
	ldap_automount_context_t *am = cookie->am_state;
	ns_ldap_return_code ret;

	ret = __ns_ldap_initSearch(cookie);
	if (ret != NS_LDAP_SUCCESS) {
		return ret;
	}

	LA_INIT(a);
	LA_TYPE(a) = LA_TYPE_NONE;

	if (cookie->sel == LM_AUTOMOUNT) {
		assert(am != NULL);

		LA_BASE(a) = am->lac_dn_list[am->lac_dn_index];
	}

	assert(cookie->mapped_filter != NULL);

	do {
		cookie->ret = -1;

		stat = _nss_ldap_getent_ex(&a, &cookie->state, cookie,
			NULL, 0, &cookie->erange,
			cookie->mapped_filter,
			cookie->sel,
			cookie->mapped_attribute,
			__ns_ldap_parseEntry);
		if (stat == NSS_NOTFOUND && cookie->sel == LM_AUTOMOUNT) {
			if (am->lac_dn_index < am->lac_dn_count - 1) {
				am->lac_dn_index++;
			} else {
				break;
			}
		}
	} while (stat == NSS_NOTFOUND);

	if (cookie->ret < 0) {
		cookie->ret = __ns_ldap_mapError(stat);
	}

	return cookie->ret;
}

ns_ldap_return_code
__ns_ldap_firstEntry(const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	void **pCookie,
	ns_ldap_result_t **result,
	ns_ldap_error_t **errorp,
	const void *userdata)
{
	ns_ldap_return_code ret;
	ns_ldap_cookie_t *cookie = NULL;

	*pCookie = NULL;
	*result = NULL;
	*errorp = NULL;

	_nss_ldap_enter();

	ret = __ns_ldap_initCookie(service, filter, init_filter_cb,
		attribute, cred, flags, &cookie, NULL, userdata);
	if (ret == NS_LDAP_SUCCESS) {
		ret = __ns_ldap_search(cookie);

		*result = cookie->result;
		cookie->result = NULL;
	}

	__ns_ldap_mapErrorDetail(ret, errorp);

	_nss_ldap_leave();

	*pCookie = cookie;

	return ret;
}

ns_ldap_return_code
__ns_ldap_nextEntry(
	void *_cookie,
	ns_ldap_result_t ** result,
	ns_ldap_error_t **errorp)
{
	ns_ldap_return_code ret;
	ns_ldap_cookie_t *cookie;

	*result = NULL;
	*errorp = NULL;

	cookie = (ns_ldap_cookie_t *)_cookie;
	if (cookie == NULL) {
		return NS_LDAP_INVALID_PARAM;
	}

	_nss_ldap_enter();

	ret = __ns_ldap_search(cookie);

	*result = cookie->result;
	cookie->result = NULL;

	__ns_ldap_mapErrorDetail(ret, errorp);

	_nss_ldap_leave();

	return ret;
}

ns_ldap_return_code
__ns_ldap_endEntry(
	void **pCookie,
	ns_ldap_error_t **errorp)
{
	ns_ldap_cookie_t *cookie;

	_nss_ldap_enter();

	cookie = (ns_ldap_cookie_t *)*pCookie;

	__ns_ldap_mapErrorDetail(cookie->ret, errorp);
	__ns_ldap_freeCookie(&cookie);

	*pCookie = NULL;

	_nss_ldap_leave();

	return NS_LDAP_SUCCESS;
}

ns_ldap_return_code
__ns_ldap_list(
	const char *map,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc, char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_result_t **result,
	ns_ldap_error_t **errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata)
{
	ns_ldap_cookie_t *cookie;
	ns_ldap_return_code ret;

	debug("==> __ns_ldap_list map=%s filter=%s", map, filter);

	*result = NULL;
	*errorp = NULL;

	_nss_ldap_enter();

	ret = __ns_ldap_initCookie(map, filter, init_filter_cb,
		attribute, cred, flags, &cookie, NULL, userdata);

	while (ret == NS_LDAP_SUCCESS) {
		ret = __ns_ldap_search(cookie);

		if (*result == NULL) {
			*result = cookie->result;
		}

		if (cookie->cb_ret != NS_LDAP_CB_NEXT) {
			break;
		}
	}

	cookie->result = NULL;
	__ns_ldap_freeCookie(&cookie);
	__ns_ldap_mapErrorDetail(ret, errorp);

	_nss_ldap_leave();

	debug("<== __ns_ldap_list ret=%s", __ns_ldap_err2str(ret));

	return ret;
}

ns_ldap_return_code
__ns_ldap_err2str(ns_ldap_return_code err, char **strmsg)
{
	switch (err) {
	case NS_LDAP_SUCCESS:
	case NS_LDAP_SUCCESS_WITH_INFO:
		*strmsg = "Success";
		break;
	case NS_LDAP_OP_FAILED:
		*strmsg = "Operation failed";
		break;
	case NS_LDAP_NOTFOUND:
		*strmsg = "Not found";
		break;
	case NS_LDAP_MEMORY:
		*strmsg = "Out of memory";
		break;
	case NS_LDAP_CONFIG:
		*strmsg = "Configuration error";
		break;
	case NS_LDAP_PARTIAL:
		*strmsg = "Partial results received";
		break;
	case NS_LDAP_INTERNAL:
		*strmsg = "Internal LDAP error";
		break;
	case NS_LDAP_INVALID_PARAM:
		*strmsg = "Invalid parameter";
		break;
	default:
		*strmsg = "Unknown error";
		return NS_LDAP_INVALID_PARAM;
		break;
	}

	return NS_LDAP_SUCCESS;
}

#endif /* HAVE_NSSWITCH_H */

