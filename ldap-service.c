
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

/*
   Determine the canonical name of the RPC with _nss_ldap_getrdnvalue(),
   and assign any values of "cn" which do NOT match this canonical name
   as aliases.
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

#ifdef GNU_NSS
#include <nss.h>
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#include <sys/byteorder.h>
#endif

#include "ldap-nss.h"
#include "ldap-service.h"
#include "globals.h"
#include "util.h"

#ifdef IRS_NSS
#include <port_after.h>
#endif

#ifdef GNU_NSS
static context_handle_t serv_context = NULL;
#endif

static NSS_STATUS
_nss_ldap_parse_serv (
		       LDAP * ld,
		       LDAPMessage * e,
		       ldap_state_t * state,
		       void *result,
		       char *buffer,
		       size_t buflen)
{
  struct servent *service = (struct servent *) result;
  char *port;
  NSS_STATUS stat = NSS_SUCCESS;

  /* this is complicated and ugly, because some git (me) specified that service
   * entries should expand to two entities (or more) if they have multi-valued
   * ipServiceProtocol fields.
   */

  if (state->ls_type == LS_TYPE_KEY)
    {
      if (state->ls_info.ls_key == NULL)
	{
	  /* non-deterministic behaviour is ok */
	  stat = _nss_ldap_assign_attrval (ld, e, LDAP_ATTR_SERVICEPROTOCOL, &service->s_proto, &buffer, &buflen);
	  if (stat != NSS_SUCCESS)
	    {
	      return stat;
	    }
	}
      else
	{
	  register int len;
	  len = strlen (state->ls_info.ls_key);
	  if (buflen < (size_t) (len + 1))
	    {
	      return NSS_TRYAGAIN;
	    }
	  strncpy (buffer, state->ls_info.ls_key, len);
	  buffer[len] = '\0';
	  service->s_proto = buffer;
	  buffer += len + 1;
	  buflen -= len + 1;
	}
    }
  else
    {
      char **vals = ldap_get_values (ld, e, LDAP_ATTR_SERVICEPROTOCOL);
      int len;
      if (vals == NULL)
	{
	  state->ls_info.ls_index = -1;
	  return NSS_NOTFOUND;
	}

      switch (state->ls_info.ls_index)
	{
	case 0:
	  /* last time. decrementing ls_index to -1 AND returning !NSS_SUCCESS
	     will force this entry to be discarded.
	   */
	  stat = NSS_NOTFOUND;
	  break;
	case -1:
	  /* first time */
	  state->ls_info.ls_index = ldap_count_values (vals);
	  /* fall off to default ... */
	default:
	  len = strlen (vals[state->ls_info.ls_index - 1]);
	  if (buflen < (size_t) (len + 1))
	    {
	      return NSS_TRYAGAIN;
	    }
	  strncpy (buffer, vals[state->ls_info.ls_index - 1], len);
	  buffer[len] = '\0';
	  service->s_proto = buffer;
	  buffer += len + 1;
	  buflen -= len + 1;
	  stat = NSS_SUCCESS;
	}

      state->ls_info.ls_index--;
    }

  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat = _nss_ldap_getrdnvalue (ld, e, LDAP_ATTR_SERVICENAME, &service->s_name, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat = _nss_ldap_assign_attrvals (ld, e, LDAP_ATTR_SERVICENAME, service->s_name, &service->s_aliases,
				    &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  stat = _nss_ldap_assign_attrval (ld, e, LDAP_ATTR_SERVICEPORT, &port, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    {
      return stat;
    }

  service->s_port = htons (atoi (port));

  return NSS_SUCCESS;
}

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_getservbyname_r (nss_backend_t * be, void *args)
{
  ldap_args_t a;
  NSS_STATUS status;

  LA_INIT (a);
  LA_STRING (a) = NSS_ARGS (args)->key.serv.serv.name;
  LA_TYPE (a) = (NSS_ARGS (args)->key.serv.proto == NULL) ?
    LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = NSS_ARGS (args)->key.serv.proto;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				(NSS_ARGS (args)->key.serv.proto == NULL) ?
				filt_getservbyname : filt_getservbynameproto,
				(const char **) serv_attributes,
				_nss_ldap_parse_serv);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  return status;
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_getservbyname_r (
			    const char *name,
			    const char *proto,
			    struct servent * result,
			    char *buffer,
			    size_t buflen,
			    int *errnop)
{
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = name;
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_STRING : LA_TYPE_STRING_AND_STRING;
  LA_STRING2 (a) = proto;

  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
	   ((proto == NULL) ? filt_getservbyname : filt_getservbynameproto),
			      (const char **) serv_attributes,
			      _nss_ldap_parse_serv);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_getservbyport_r (nss_backend_t * be, void *args)
{
  ldap_args_t a;
  NSS_STATUS status;

  LA_INIT (a);
  LA_NUMBER (a) = htons (NSS_ARGS (args)->key.serv.serv.port);
  LA_TYPE (a) = (NSS_ARGS (args)->key.serv.proto == NULL) ?
    LA_TYPE_NUMBER : LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2 (a) = NSS_ARGS (args)->key.serv.proto;

  status = _nss_ldap_getbyname (&a,
				NSS_ARGS (args)->buf.result,
				NSS_ARGS (args)->buf.buffer,
				NSS_ARGS (args)->buf.buflen,
				&NSS_ARGS (args)->erange,
				(NSS_ARGS (args)->key.serv.proto == NULL) ?
				filt_getservbyport : filt_getservbyportproto,
				(const char **) serv_attributes,
				_nss_ldap_parse_serv);

  if (status == NSS_SUCCESS)
    NSS_ARGS (args)->returnval = NSS_ARGS (args)->buf.result;

  return status;
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_getservbyport_r (
			    int port,
			    const char *proto,
			    struct servent * result,
			    char *buffer,
			    size_t buflen,
			    int *errnop)
{
  ldap_args_t a;

  LA_INIT (a);
  LA_NUMBER (a) = htons (port);
  LA_TYPE (a) = (proto == NULL) ? LA_TYPE_NUMBER : LA_TYPE_NUMBER_AND_STRING;
  LA_STRING2 (a) = proto;
  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
	     (proto == NULL) ? filt_getservbyport : filt_getservbyportproto,
			      (const char **) serv_attributes,
			      _nss_ldap_parse_serv);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_setservent_r (nss_backend_t * serv_context, void *args)
#elif defined(GNU_NSS)
     NSS_STATUS _nss_ldap_setservent (void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_SETENT (serv_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_endservent_r (nss_backend_t * serv_context, void *args)
#elif defined(GNU_NSS)
     NSS_STATUS _nss_ldap_endservent (void)
#endif
#if defined(GNU_NSS) || defined(SUN_NSS)
{
  LOOKUP_ENDENT (serv_context);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_getservent_r (nss_backend_t * serv_context, void *args)
{
  LOOKUP_GETENT (args, serv_context, filt_getservent, serv_attributes, _nss_ldap_parse_serv);
}
#elif defined(GNU_NSS)
NSS_STATUS
_nss_ldap_getservent_r (struct servent *result, char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (serv_context, result, buffer, buflen, errnop, filt_getservent, serv_attributes, _nss_ldap_parse_serv);
}
#endif

#ifdef SUN_NSS
static NSS_STATUS
_nss_ldap_services_destr (nss_backend_t * serv_context, void *args)
{
  return _nss_ldap_default_destr (serv_context, args);
}

static nss_backend_op_t services_ops[] =
{
  _nss_ldap_services_destr,
  _nss_ldap_endservent_r,
  _nss_ldap_setservent_r,
  _nss_ldap_getservent_r,
  _nss_ldap_getservbyname_r,
  _nss_ldap_getservbyport_r
};

nss_backend_t *
_nss_ldap_services_constr (const char *db_name,
			   const char *src_name,
			   const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = services_ops;
  be->n_ops = sizeof (services_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}

#endif /* !GNU_NSS */

#ifdef IRS_NSS
#include "irs-service.c"
#endif
