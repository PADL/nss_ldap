/* Copyright (C) 2005 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2005.

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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-automount.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H

static NSS_STATUS
_nss_ldap_parse_automount (LDAPMessage * e,
			   ldap_state_t * pvt,
			   void *result, char *buffer, size_t buflen)
{
  NSS_STATUS stat;
  char ***keyval = result;

  stat = 
    _nss_ldap_assign_attrval (e, AT (automountKey), keyval[0],
			      &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat = 
    _nss_ldap_assign_attrval (e, AT (automountInformation), keyval[1],
			      &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  return NSS_SUCCESS;
}

static NSS_STATUS
am_context_alloc(ldap_automount_context_t **pContext)
{
  ldap_automount_context_t *context;

  context = (ldap_automount_context_t *)malloc (sizeof(*context));
  if (context == NULL)
    {
      return NSS_TRYAGAIN;
    }

  context->lac_dn = NULL;

  if (_nss_ldap_ent_context_init_locked (&context->lac_state) == NULL)
    {
      free (context->lac_dn);
      free (context);
      return NSS_UNAVAIL;
    }

  *pContext = context;

  return NSS_SUCCESS;
}

static void
am_context_free(ldap_automount_context_t **pContext)
{
  ldap_automount_context_t *context;

  context = *pContext;

  if (context == NULL)
    return;

  if (context->lac_dn != NULL)
#ifdef HAVE_LDAP_MEMFREE
    ldap_memfree (context->lac_dn);
#else
    free (context->lac_dn);
#endif

  _nss_ldap_ent_context_release (context->lac_state);

  memset (context, 0, sizeof (*context));
  free (context);

  *pContext = NULL;

  return;
}

NSS_STATUS _nss_ldap_setautomntent(const char *mapname, void **private)
{
  ldap_automount_context_t *context = NULL;
  LDAPMessage *res = NULL, *e;
  const char *no_attrs[] = { NULL };
  ldap_args_t a;
  NSS_STATUS stat;

  debug ("==> _nss_ldap_setautomntent");

  _nss_ldap_enter ();

  stat = am_context_alloc (&context);
  if (stat != NSS_SUCCESS)
    {
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return stat;
    }

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = mapname;

  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_setautomntent,
			     LM_AUTOMOUNT, no_attrs, 1, &res);
  if (stat != NSS_SUCCESS)
    {
      am_context_free (&context);
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return stat;
    }

  e = _nss_ldap_first_entry (res);
  if (e == NULL)
    {
      ldap_msgfree (res);
      am_context_free (&context);
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return NSS_NOTFOUND;
    }

  context->lac_dn = _nss_ldap_get_dn (e);
  if (context->lac_dn == NULL)
    {
      ldap_msgfree (res);
      am_context_free (&context);
      _nss_ldap_leave ();
      debug ("<== _nss_ldap_setautomntent");
      return NSS_NOTFOUND;
    }

  ldap_msgfree (res);
  *private = context;
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_setautomntent");

  return NSS_SUCCESS;
}

NSS_STATUS _nss_ldap_getautomntent_r(void *private, const char **key, const char **value,
				     char *buffer, size_t buflen, int *errnop)
{
  NSS_STATUS stat;
  ldap_automount_context_t *context = (ldap_automount_context_t *)private;
  ldap_args_t a;
  char **keyval[2];

  if (context == NULL)
    return NSS_NOTFOUND;

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_NONE;
  LA_BASE (a) = context->lac_dn;

  keyval[0] = (char **)key;
  keyval[1] = (char **)value;

  debug ("==> _nss_ldap_getautomntent_r");

  _nss_ldap_enter ();

  stat = _nss_ldap_getent_ex (&a, &context->lac_state,
			      (void *)keyval,
			      buffer, buflen, errnop,
			      _nss_ldap_filt_getautomntent,
			      LM_AUTOMOUNT,
			      NULL,
			      _nss_ldap_parse_automount);
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_getautomntent_r");

  return stat;
}

NSS_STATUS _nss_ldap_endautomntent(void **private)
{
  ldap_automount_context_t **pContext = (ldap_automount_context_t **)private;

  debug ("==> _nss_ldap_endautomntent");

  _nss_ldap_enter ();
  am_context_free (pContext);
  _nss_ldap_leave ();

  debug ("<== _nss_ldap_endautomntent");

  return NSS_SUCCESS;
}

#endif /* HAVE_NSS_H */

