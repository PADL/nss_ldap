/* Copyright (C) 1997-2004 Luke Howard.
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
 */

static char rcsId[] =
  "$Id$";

#include "config.h"

#ifdef HAVE_PORT_BEFORE_H
#include <port_before.h>
#endif

#ifdef HAVE_THREAD_H
#include <thread.h>
#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <grp.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif

#include "ldap-nss.h"
#include "ldap-grp.h"
#include "util.h"

#ifdef HAVE_PORT_AFTER_H
#include <port_after.h>
#endif

#ifdef HAVE_NSS_H
static ent_context_t *gr_context = NULL;
#endif

#ifdef RFC2307BIS
static char *_nss_ldap_no_members[] = { NULL };
#endif

#ifdef AIX
typedef struct ldap_initgroups_args
{
  char **grplist;
  size_t listlen;
}
ldap_initgroups_args_t;
#else
# ifdef HAVE_NSSWITCH_H
typedef struct nss_groupsbymem ldap_initgroups_args_t;
# else
typedef struct ldap_initgroups_args
{
  gid_t group;
  long int *start;
  long int *size;
  gid_t **groups;
  long int limit;
}
ldap_initgroups_args_t;
# endif
#endif /* AIX */

static NSS_STATUS
_nss_ldap_parse_gr (LDAP * ld,
		    LDAPMessage * e,
		    ldap_state_t * pvt,
		    void *result, char *buffer, size_t buflen)
{
  struct group *gr = (struct group *) result;
  char *gid;
  NSS_STATUS stat;
#ifdef RFC2307BIS
  char **uid_mems, **dn_mems, **vals;
  size_t uid_mems_c = 0, dn_mems_c = 0;
#endif /* RFC2307BIS */

  stat =
    _nss_ldap_assign_attrval (ld, e, ATM (group, gidNumber), &gid, &buffer,
			      &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  gr->gr_gid =
    (*gid == '\0') ? (unsigned) GID_NOBODY : (gid_t) strtoul (gid,
							      (char **) NULL,
							      10);

  stat =
    _nss_ldap_getrdnvalue (ld, e, ATM (group, cn), &gr->gr_name, &buffer,
			   &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

  stat =
    _nss_ldap_assign_userpassword (ld, e, ATM (group, userPassword),
				   &gr->gr_passwd, &buffer, &buflen);
  if (stat != NSS_SUCCESS)
    return stat;

#ifndef RFC2307BIS
  stat =
    _nss_ldap_assign_attrvals (ld, e, AT (memberUid), NULL, &gr->gr_mem,
			       &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;
#else
  dn_mems = NULL;
  vals = ldap_get_values (ld, e, AT (uniqueMember));
  if (vals != NULL)
    {
      char **mem_p, **valiter;

      dn_mems_c = ldap_count_values (vals);

      if (bytesleft (buffer, buflen, char *) <
	  (dn_mems_c + 1) * sizeof (char *))
	{
	  ldap_value_free (vals);
	  return NSS_TRYAGAIN;
	}
      align (buffer, buflen, char *);
      mem_p = dn_mems = (char **) buffer;
      buffer += (dn_mems_c + 1) * sizeof (char *);
      buflen -= (dn_mems_c + 1) * sizeof (char *);
      for (valiter = vals; *valiter != NULL; valiter++)
	{
	  char *uid;

	  /*
	   * Remove optional UID (as in unique identifier)
	   * only for uniqueMember; member does not have UID
	   */
	  if ((uid = strrchr (*valiter, '#')) != NULL)
	    {
	      *uid = '\0';
	    }

	  stat = _nss_ldap_dn2uid (ld, *valiter, &uid, &buffer, &buflen);
	  switch (stat)
	    {
	    case NSS_SUCCESS:
	      *mem_p = uid;
	      mem_p++;
	      break;
	    case NSS_TRYAGAIN:
	      ldap_value_free (vals);
	      return NSS_TRYAGAIN;
	      break;
	    case NSS_NOTFOUND:
	    default:
	      dn_mems_c--;
	      break;
	    }
	}
      ldap_value_free (vals);
    }

  stat =
    _nss_ldap_assign_attrvals (ld, e, AT (memberUid), NULL, &uid_mems,
			       &buffer, &buflen, &uid_mems_c);

  if (stat == NSS_TRYAGAIN)
    return NSS_TRYAGAIN;

  if (stat != NSS_SUCCESS)
    uid_mems = NULL;

  if (dn_mems == NULL)
    {
      if (uid_mems == NULL)
	gr->gr_mem = _nss_ldap_no_members;
      else
	gr->gr_mem = uid_mems;
    }
  else
    {
      if (uid_mems == NULL)
	gr->gr_mem = dn_mems;
      else
	{
	  if (bytesleft (buffer, buflen, char *) <
	      (dn_mems_c + uid_mems_c + 1) * sizeof (char *))
	      return NSS_TRYAGAIN;
	  align (buffer, buflen, char *);
	  gr->gr_mem = (char **) buffer;
	  buffer += (dn_mems_c + uid_mems_c + 1) * sizeof (char *);
	  buflen -= (dn_mems_c + uid_mems_c + 1) * sizeof (char *);
	  memcpy (gr->gr_mem, dn_mems, (dn_mems_c * sizeof (char *)));
	  memcpy (&gr->gr_mem[dn_mems_c], uid_mems,
		  (uid_mems_c * sizeof (char *)));
	  gr->gr_mem[dn_mems_c + uid_mems_c] = NULL;
	}
    }
#endif /* RFC2307BIS */

  return NSS_SUCCESS;
}

/*
 * Add a group to a group list.
 */
static NSS_STATUS
do_parse_initgroups (LDAP * ld, LDAPMessage * e,
		     ldap_state_t * pvt, void *result,
		     char *buffer, size_t buflen)
{
  char **values;
  ssize_t i;
  gid_t gid;
  ldap_initgroups_args_t *lia = (ldap_initgroups_args_t *) result;

  values = _nss_ldap_get_values (e, ATM (group, gidNumber));
  if (values == NULL)
    {
      /* invalid group; skip it */
      return NSS_SUCCESS;
    }

#ifdef AIX
  i = strlen (values[0]);
  lia->grplist = realloc (lia->grplist, lia->listlen + i + 2);
  if (lia->grplist == NULL)
    {
      ldap_value_free (values);
      return NSS_TRYAGAIN;
    }
  memcpy (lia->grplist + lia->listlen, values[0], i);
  lia->grplist[lia->listlen + i] = '.';
  lia->listlen += i + 1;
  ldap_value_free (values);
#else
  gid = strtoul (values[0], (char **) NULL, 10);
  ldap_value_free (values);
  if (gid == LONG_MAX && errno == ERANGE)
    {
      /* invalid group, skip it */
      return NSS_SUCCESS;
    }

# ifdef HAVE_NSSWITCH_H
  /* weed out duplicates; is this really our resposibility? */
  for (i = 0; i < lia->numgids; i++)
    {
      if (lia->gid_array[i] == (gid_t) gid)
	return NSS_SUCCESS;
    }

  if (lia->numgids == lia->maxgids)
    {
      /* can't fit any more */
      return NSS_SUCCESS;
    }

  lia->gid_array[lia->numgids++] = (gid_t) gid;
# else
  if (gid == lia->group)
    {
      /* primary group, so skip it */
      return NSS_SUCCESS;
    }

  if (*(lia->start) == *(lia->size) && lia->limit <= 0)
    {
      /* Need a bigger buffer */
      *(lia->groups) = (gid_t *) realloc (*(lia->groups),
					  2 * *(lia->size) *
					  sizeof (gid_t));
      if (*(lia->groups) == NULL)
	{
	  return NSS_TRYAGAIN;
	}
      *(lia->size) *= 2;
    }
  /* weed out duplicates; is this really our responsibility? */
  for (i = 0; i < *(lia->start); i++)
    {
      if ((*(lia->groups))[i] == gid)
	{
	  return NSS_SUCCESS;
	}
    }

  /* add to group list */
  *(lia->groups)[*(lia->start)] = gid;
  *(lia->start) += 1;

  if (*(lia->start) == lia->limit)
    {
      /* can't fit any more */
      return NSS_SUCCESS;
    }
# endif				/* HAVE_NSSWITCH_H */
#endif /* AIX */

  return NSS_SUCCESS;
}

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H) || defined(AIX)
#ifdef HAVE_NSS_H
NSS_STATUS _nss_ldap_initgroups_dyn (const char *user, gid_t group,
				     long int *start, long int *size,
				     gid_t ** groupsp, long int limit,
				     int *errnop);

NSS_STATUS
_nss_ldap_initgroups (const char *user, gid_t group, long int *start,
		      long int *size, gid_t * groups, long int limit,
		      int *errnop)
{
  return (_nss_ldap_initgroups_dyn (user, group, start, size, &groups, limit,
				    errnop));
}
#endif
#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_getgroupsbymember_r (nss_backend_t * be, void *args)
#elif defined(HAVE_NSS_H)
  NSS_STATUS
_nss_ldap_initgroups_dyn (const char *user, gid_t group, long int *start,
			  long int *size, gid_t ** groupsp, long int limit,
			  int *errnop)
#elif defined(AIX)
     char *_nss_ldap_getgrset (char *user)
#endif
{
#ifdef HAVE_NSSWITCH_H
  ldap_initgroups_args_t *liap = (struct nss_groupsbymem *) args;
#else
  ldap_initgroups_args_t lia;
  ldap_initgroups_args_t *liap = &lia;
#endif /* HAVE_NSSWITCH_H */
#ifndef HAVE_NSS_H
  int erange = 0;
#endif /* HAVE_NSS_H */
#ifdef RFC2307BIS
  char *userdn = NULL;
  LDAPMessage *res, *e;
#endif /* RFC2307BIS */
  const char *filter;
  ldap_args_t a;
  NSS_STATUS stat;
  ent_context_t *ctx = NULL;

  LA_INIT (a);
#if defined(HAVE_NSS_H) || defined(AIX)
  LA_STRING (a) = user;
#else
  LA_STRING (a) = liap->username;
#endif /* HAVE_NSS_H || AIX */
  LA_TYPE (a) = LA_TYPE_STRING;

#ifdef AIX
  lia.grplist = NULL;
  lia.listlen = 0;
#elif !defined(HAVE_NSSWITCH_H)
  lia.group = group;
  lia.start = start;
  lia.size = size;
  lia.groups = groupsp;
  lia.limit = limit;
#endif /* AIX */

  _nss_ldap_enter ();

#ifdef RFC2307BIS
  /* initialize schema */
  stat = _nss_ldap_init ();
  if (stat != NSS_SUCCESS)
    {
      _nss_ldap_leave ();
# ifdef AIX
      return NULL;
# else
      return stat;
# endif /* !AIX */
    }

  /* lookup the user's DN. */
  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getpwnam, LM_PASSWD, 1, &res);
  if (stat == NSS_SUCCESS)
    {
      e = _nss_ldap_first_entry (res);
      if (e != NULL)
	{
	  userdn = _nss_ldap_get_dn (e);
	}
      ldap_msgfree (res);
    }
  if (userdn != NULL)
    {
      LA_STRING2 (a) = userdn;
      LA_TYPE (a) = LA_TYPE_STRING_AND_STRING;
      filter = _nss_ldap_filt_getgroupsbymemberanddn;
    }
  else
    {
      filter = _nss_ldap_filt_getgroupsbymember;
    }

  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      _nss_ldap_leave ();
# ifdef AIX
      return NULL;
# else
      return NSS_UNAVAIL;
# endif /* AIX */
    }
#else
  filter = _nss_ldap_filt_getgroupsbymember;
#endif /* RFC2307BIS */

  stat = _nss_ldap_getent_ex (&a, &ctx, (void *) liap, NULL, 0,
#ifdef HAVE_NSS_H
			      errnop,
#else
			      &erange,
#endif /* HAVE_NSS_H */
			      filter, LM_GROUP, do_parse_initgroups);

#ifdef RFC2307BIS
  if (userdn != NULL)
    {
#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (userdn);
#else
      free (userdn);
#endif /* HAVE_LDAP_MEMFREE */
    }
#endif /* RFC2307BIS */

  if (stat != NSS_SUCCESS)
    {
#ifndef HAVE_NSS_H
      if (erange)
	errno = ERANGE;
#endif /* HAVE_NSS_H */
      _nss_ldap_leave ();
#ifndef AIX
      return stat;
#else
      return NULL;
#endif
    }

  _nss_ldap_leave ();

#ifdef HAVE_NSS_H
  return NSS_SUCCESS;
#elif defined(AIX)
  /* Strip last comma and terminate the string */
  if (lia.grplist != NULL && lia.listlen != 0)
    lia.grplist[lia.listlen - 1] = '\0';
  return lia.grplist;
#else
  /* yes, NSS_NOTFOUND is the successful errno code. see nss_dbdefs.h */
  return NSS_NOTFOUND;
#endif /* HAVE_NSS_H */
}
#endif /* HAVE_NSSWITCH_H || HAVE_NSS_H || AIX */

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getgrnam_r (const char *name,
		      struct group * result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NAME (name, result, buffer, buflen, errnop, _nss_ldap_filt_getgrnam,
	       LM_GROUP, _nss_ldap_parse_gr);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getgrnam_r (nss_backend_t * be, void *args)
{
  LOOKUP_NAME (args, _nss_ldap_filt_getgrnam, LM_GROUP, _nss_ldap_parse_gr);
}
#endif

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getgrgid_r (gid_t gid,
		      struct group *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_NUMBER (gid, result, buffer, buflen, errnop, _nss_ldap_filt_getgrgid,
		 LM_GROUP, _nss_ldap_parse_gr);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getgrgid_r (nss_backend_t * be, void *args)
{
  LOOKUP_NUMBER (args, key.gid, _nss_ldap_filt_getgrgid, LM_GROUP,
		 _nss_ldap_parse_gr);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_setgrent (void)
{
  LOOKUP_SETENT (gr_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_setgrent_r (nss_backend_t * gr_context, void *args)
{
  LOOKUP_SETENT (gr_context);
}
#endif

#if defined(HAVE_NSS_H)
NSS_STATUS
_nss_ldap_endgrent (void)
{
  LOOKUP_ENDENT (gr_context);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_endgrent_r (nss_backend_t * gr_context, void *args)
{
  LOOKUP_ENDENT (gr_context);
}
#endif

#ifdef HAVE_NSS_H
NSS_STATUS
_nss_ldap_getgrent_r (struct group *result,
		      char *buffer, size_t buflen, int *errnop)
{
  LOOKUP_GETENT (gr_context, result, buffer, buflen, errnop,
		 _nss_ldap_filt_getgrent, LM_GROUP, _nss_ldap_parse_gr);
}
#elif defined(HAVE_NSSWITCH_H)
static NSS_STATUS
_nss_ldap_getgrent_r (nss_backend_t * gr_context, void *args)
{
  LOOKUP_GETENT (args, gr_context, _nss_ldap_filt_getgrent, LM_GROUP,
		 _nss_ldap_parse_gr);
}
#endif

#ifdef HAVE_NSSWITCH_H
static NSS_STATUS
_nss_ldap_group_destr (nss_backend_t * gr_context, void *args)
{
  return _nss_ldap_default_destr (gr_context, args);
}

static nss_backend_op_t group_ops[] = {
  _nss_ldap_group_destr,
  _nss_ldap_endgrent_r,
  _nss_ldap_setgrent_r,
  _nss_ldap_getgrent_r,
  _nss_ldap_getgrnam_r,
  _nss_ldap_getgrgid_r,
  _nss_ldap_getgroupsbymember_r
};

nss_backend_t *
_nss_ldap_group_constr (const char *db_name,
			const char *src_name, const char *cfg_args)
{
  nss_ldap_backend_t *be;

  if (!(be = (nss_ldap_backend_t *) malloc (sizeof (*be))))
    return NULL;

  be->ops = group_ops;
  be->n_ops = sizeof (group_ops) / sizeof (nss_backend_op_t);

  /* a NOOP at the moment */
  if (_nss_ldap_default_constr (be) != NSS_SUCCESS)
    return NULL;

  return (nss_backend_t *) be;
}


#endif /* !HAVE_NSS_H */

#ifdef HAVE_IRS_H
#include "irs-grp.c"
#endif
