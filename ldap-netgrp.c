/* Copyright (C) 2002 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Larry Lile, <llile@dreamworks.com>, 2002.

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

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#ifdef HAVE_THREAD_H
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-netgrp.h"
#include "globals.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *netgroup_context = NULL;
#endif

/*
 * I pulled the following macro (EXPAND), functions (strip_whitespace and
 * _nss_netgroup_parseline) and structures (name_list and __netgrent) from
 * glibc-2.2.x.  _nss_netgroup_parseline became _nss_ldap_parse_netgr after
 * some modification. 
 * 
 * The rest of the code is modeled on various other _nss_ldap functions.
 */

#define EXPAND(needed)                                                        \
  do                                                                          \
    {                                                                         \
      size_t old_cursor = result->cursor - result->data;                      \
                                                                              \
      result->data_size += 512 > 2 * needed ? 512 : 2 * needed;               \
      result->data = realloc (result->data, result->data_size);               \
                                                                              \
      if (result->data == NULL)                                               \
        {                                                                     \
          stat = NSS_UNAVAIL;                                                 \
          goto the_end;                                                       \
        }                                                                     \
                                                                              \
      result->cursor = result->data + old_cursor;                             \
    }                                                                         \
  while (0)

/* A netgroup can consist of names of other netgroups.  We have to
   track which netgroups were read and which still have to be read.  */
struct name_list
{
  const char *name;
  struct name_list *next;
};


/* Dataset for iterating netgroups.  */
struct __netgrent
{
  enum
  { triple_val, group_val }
  type;

  union
  {
    struct
    {
      const char *host;
      const char *user;
      const char *domain;
    }
    triple;

    const char *group;
  }
  val;

  /* Room for the data kept between the calls to the netgroup
     functions.  We must avoid global variables.  */
  char *data;
  size_t data_size;
  char *cursor;
  int first;

  struct name_list *known_groups;
  struct name_list *needed_groups;
};

static char *
strip_whitespace (char *str)
{
  char *cp = str;

  /* Skip leading spaces.  */
  while (isspace (*cp))
    cp++;

  str = cp;
  while (*cp != '\0' && !isspace (*cp))
    cp++;

  /* Null-terminate, stripping off any trailing spaces.  */
  *cp = '\0';

  return *str == '\0' ? NULL : str;
}

static NSS_STATUS
_nss_ldap_parse_netgr (void *vresultp, char *buffer, size_t buflen)
{
  struct __netgrent *result = (struct __netgrent *) vresultp;
  char *cp = result->cursor;
  char *user, *host, *domain;

  /* The netgroup either doesn't exist or is empty. */
  if (cp == NULL)
    return NSS_RETURN;

  /* First skip leading spaces. */
  while (isspace (*cp))
    ++cp;

  if (*cp != '(')
    {
      /* We have a list of other netgroups. */
      char *name = cp;

      while (*cp != '\0' && !isspace (*cp))
	++cp;

      if (name != cp)
	{
	  /* It is another netgroup name. */
	  int last = *cp == '\0';

	  result->type = group_val;
	  result->val.group = name;
	  *cp = '\0';
	  if (!last)
	    ++cp;
	  result->cursor = cp;
	  result->first = 0;

	  return NSS_SUCCESS;
	}
      return result->first ? NSS_NOTFOUND : NSS_RETURN;
    }

  /* Match host name. */
  host = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;

  /* Match user name. */
  user = ++cp;
  while (*cp != ',')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;

  /* Match domain name. */
  domain = ++cp;
  while (*cp != ')')
    if (*cp++ == '\0')
      return result->first ? NSS_NOTFOUND : NSS_RETURN;
  ++cp;

  /* When we got here we have found an entry.  Before we can copy it
     to the private buffer we have to make sure it is big enough.  */
  if (cp - host > buflen)
    return NSS_UNAVAIL;

  strncpy (buffer, host, cp - host);
  result->type = triple_val;

  buffer[(user - host) - 1] = '\0';
  result->val.triple.host = strip_whitespace (buffer);

  buffer[(domain - host) - 1] = '\0';
  result->val.triple.user = strip_whitespace (buffer + (user - host));

  buffer[(cp - host) - 1] = '\0';
  result->val.triple.domain = strip_whitespace (buffer + (domain - host));

  /* Remember where we stopped reading. */
  result->cursor = cp;
  result->first = 0;

  return NSS_SUCCESS;
}

static NSS_STATUS
_nss_ldap_load_netgr (LDAP * ld,
		      LDAPMessage * e,
		      ldap_state_t * pvt,
		      void *vresultp, char *buffer, size_t buflen)
{
  int attr;
  int nvals;
  int valcount = 0;
  char **vals;
  char **valiter;
  struct __netgrent *result = vresultp;
  NSS_STATUS stat = NSS_SUCCESS;

  for (attr = 0; attr < 2; attr++)
    {
      switch (attr)
	{
	case 1:
	  vals = ldap_get_values (ld, e, AT (nisNetgroupTriple));
	  break;
	default:
	  vals = ldap_get_values (ld, e, AT (memberNisNetgroup));
	  break;
	}

      nvals = ldap_count_values (vals);

      if (vals == NULL)
	continue;

      if (nvals == 0)
	{
	  ldap_value_free (vals);
	  continue;
	}

      if (result->data_size > 0
	  && result->cursor - result->data + 1 > result->data_size)
	EXPAND (1);

      if (result->data_size > 0)
	*result->cursor++ = ' ';

      valcount += nvals;
      valiter = vals;

      while (*valiter != NULL)
	{
	  int curlen = strlen (*valiter);
	  if (result->cursor - result->data + curlen + 1 > result->data_size)
	    EXPAND (curlen + 1);
	  memcpy (result->cursor, *valiter, curlen + 1);
	  result->cursor += curlen;
	  valiter++;
	  if (*valiter != NULL)
	    *result->cursor++ = ' ';
	}
      ldap_value_free (values);
    }

  result->first = 1;
  result->cursor = result->data;

the_end:

  return stat;
}

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_endnetgrent (struct __netgrent * result)
{
  if (result->data != NULL)
    {
      free (result->data);
      result->data = NULL;
      result->data_size = 0;
      result->cursor = NULL;
    }

  LOOKUP_ENDENT (netgroup_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_endnetgrent_r (nss_backend_t * be, struct __netgrent *result)
{
  if (result->data != NULL)
    {
      free (result->data);
      result->data = NULL;
      result->data_size = 0;
      result->cursor = NULL;
    }

  LOOKUP_ENDENT (be);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_setnetgrent (char *group, struct __netgrent *result)
{
  int errnop = 0, buflen = 0;
  char *buffer = (char *) NULL;
  ldap_args_t a;
  NSS_STATUS stat = NSS_SUCCESS;

  if (group[0] == '\0')
    return NSS_UNAVAIL;

  if (result->data != NULL)
    free (result->data);
  result->data = result->cursor = NULL;
  result->data_size = 0;

  LA_INIT (a);
  LA_STRING (a) = group;
  LA_TYPE (a) = LA_TYPE_STRING;

  stat =
    _nss_ldap_getbyname (&a, result, buffer, buflen, &errnop,
			 _nss_ldap_filt_getnetgrent, LM_NETGROUP,
			 _nss_ldap_load_netgr);

  if (errnop != 0)
    debug ("***errnop == %d", errnop);

  LOOKUP_SETENT (netgroup_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_setnetgrent_r (nss_backend_t * be, void *result)
{
  int errnop = 0, buflen = 0;
  char *buffer = (char *) NULL;
  ldap_args_t a;
  NSS_STATUS stat = NSS_SUCCESS;

  if (group[0] == '\0')
    return NSS_UNAVAIL;

  if (result->data != NULL)
    free (result->data);
  result->data = result->cursor = NULL;
  result->data_size = 0;

  LA_INIT (a);
  LA_STRING (a) = group;
  LA_TYPE (a) = LA_TYPE_STRING;

  stat =
    _nss_ldap_getbyname (&a, result, buffer, buflen, &errnop,
			 _nss_ldap_filt_getnetgrent, LM_NETGROUP,
			 _nss_ldap_load_netgr);

  LOOKUP_SETENT (be);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_getnetgrent_r (struct __netgrent *result,
			 char *buffer, size_t buflen, int *errnop)
{
  return _nss_ldap_parse_netgr (result, buffer, buflen);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getnetgrent_r (nss_backend_t * be, struct __netgrent *result)
{
  ldap_args_t a;

  LA_INIT (a);
  LA_STRING (a) = result->data;
  LA_TYPE (a) = LA_TYPE_STRING;

  return _nss_ldap_getbyname (&a, result, buffer, buflen, errnop,
			      _nss_ldap_filt_getnetgrent, LM_NETGROUP,
			      _nss_ldap_parse_netgr);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_netgroup_destr (nss_backend_t * netgroup_context, void *args)
{
  return _nss_ldap_default_destr (netgroup_context, args);
}


static nss_backend_op_t netgroup_ops[] = {
  _nss_ldap_netgroup_destr,
  _nss_ldap_setnetgrent_r,	/* NSS_DBOP_SETENT */
  _nss_ldap_endnetgrent_r,	/* NSS_DBOP_ENDENT */
  _nss_ldap_getnetgrent_r	/* NSS_DBOP_GETENT */
};

nss_backend_t *
_nss_ldap_netgroup_constr (const char *db_name,
			   const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = netgroup_ops;
  be->n_ops = sizeof (netgroup_ops) / sizeof (nss_backend_op_t);

  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}
#endif /* !HAVE_NSS_H */
