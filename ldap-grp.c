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

#if defined(HAVE_THREAD_H) && !defined(_AIX)
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

#ifdef HAVE_USERSEC_H
typedef struct ldap_initgroups_args
{
  char *grplist;
  size_t listlen;
  int depth;
  struct name_list *known_groups;
}
ldap_initgroups_args_t;
#else
# ifdef HAVE_NSSWITCH_H
typedef struct ldap_initgroups_args
{
  struct nss_groupsbymem *gbm;
  int depth;
  struct name_list *known_groups;
}
ldap_initgroups_args_t;
# else
typedef struct ldap_initgroups_args
{
  gid_t group;
  long int *start;
  long int *size;
  gid_t **groups;
  long int limit;
  int depth;
  struct name_list *known_groups;
}
ldap_initgroups_args_t;
# endif
#endif /* HAVE_USERSEC_H */

#ifdef RFC2307BIS
static NSS_STATUS
ng_chase (LDAP * ld, const char *dn, ldap_initgroups_args_t * lia);

/*
 * Range retrieval logic was reimplemented from example in
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/ldap/ldap/searching_using_range_retrieval.asp
 */

static NSS_STATUS
do_parse_range (const char *attributeType,
		const char *attributeDescription, int *start, int *end)
{
  NSS_STATUS stat = NSS_NOTFOUND;
  char *attribute;
  size_t attributeTypeLength;
  size_t attributeDescriptionLength;
  char *p;
#ifdef HAVE_STRTOK_R
  char *st = NULL;
#endif

  *start = 0;
  *end = -1;

  if (strcasecmp (attributeType, attributeDescription) == 0)
    {
      return NSS_SUCCESS;
    }

  attributeDescriptionLength = strlen (attributeDescription);
  attributeTypeLength = strlen (attributeType);

  if (attributeDescriptionLength < attributeTypeLength)
    {
      /* could not be a subtype */
      return NSS_NOTFOUND;
    }

  /* XXX need to copy as strtok() is destructive */
  attribute = strdup (attributeDescription);
  if (attribute == NULL)
    {
      return NSS_TRYAGAIN;
    }

#ifndef HAVE_STRTOK_R
  for (p = strtok (attribute, ";"); p != NULL; p = strtok (NULL, ";"))
#else
  for (p = strtok_r (attribute, ";", &st);
       p != NULL; p = strtok_r (NULL, ";", &st))
#endif /* !HAVE_STRTOK_R */
    {
      char *q;

      if (p == attribute)
	{
	  if (strcasecmp (p, attributeType) != 0)
	    {
	      free (attribute);
	      return NSS_NOTFOUND;
	    }
	}
      else if (strncasecmp (p, "range=", sizeof ("range=") - 1) == 0)
	{
	  p += sizeof ("range=") - 1;

	  q = strchr (p, '-');
	  if (q == NULL)
	    {
	      free (attribute);
	      return NSS_NOTFOUND;
	    }

	  *q++ = '\0';

	  *start = strtoul (p, (char **) NULL, 10);
	  if (strcmp (q, "*") == 0)
	    *end = -1;
	  else
	    *end = strtoul (q, (char **) NULL, 10);

	  stat = NSS_SUCCESS;
	  break;
	}
    }

  free (attribute);
  return stat;
}

static NSS_STATUS
do_get_range_values (LDAP * ld,
		     LDAPMessage * e,
		     const char *attributeType,
		     int *start, int *end, char ***pGroupMembers)
{
  NSS_STATUS stat = NSS_NOTFOUND;
  BerElement *ber = NULL;
  char *attribute;

  *pGroupMembers = NULL;

  for (attribute = ldap_first_attribute (ld, e, &ber);
       attribute != NULL; attribute = ldap_next_attribute (ld, e, ber))
    {
      stat = do_parse_range (attributeType, attribute, start, end);
      if (stat == NSS_SUCCESS)
	{
	  *pGroupMembers = ldap_get_values (ld, e, attribute);
	  if (*pGroupMembers == NULL)
	    {
	      stat = NSS_NOTFOUND;
	    }
	  else if ((*pGroupMembers)[0] == NULL)
	    {
	      ldap_value_free (*pGroupMembers);
	      *pGroupMembers = NULL;
	      stat = NSS_NOTFOUND;
	    }
	}

#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (attribute);
#endif

      if (stat == NSS_SUCCESS)
	break;
    }

  if (ber != NULL)
    ber_free (ber, 0);

  return stat;
}

/*
 * Format an attribute with description as:
 *	attribute;range=START-END
 */
static NSS_STATUS
do_construct_range_attribute (const char *attribute,
			      int start,
			      int end,
			      char **buffer,
			      size_t * buflen,
			      const char **pAttributeWithRange)
{
  size_t len;
  char startbuf[32], endbuf[32];

  snprintf (startbuf, sizeof (startbuf), "%u", start);

  if (end != -1)
    snprintf (endbuf, sizeof (endbuf), "%u", end);
  else
    snprintf (endbuf, sizeof (endbuf), "*");

  len = strlen (attribute) + sizeof (";range=") - 1;
  len += strlen (startbuf) + 1 /* - */  + strlen (endbuf);
  len++;			/* \0 */

  if (*buflen < len)
    return NSS_TRYAGAIN;

  *pAttributeWithRange = *buffer;

  snprintf (*buffer, len, "%s;range=%s-%s", attribute, startbuf, endbuf);

  *buffer += len;
  *buflen -= len;

  return NSS_SUCCESS;
}

/* 
 * Expand group members, including nested groups
 */
static NSS_STATUS
do_parse_group_members (LDAP * ld,
			LDAPMessage * e,
			char ***pGroupMembers,
			size_t * pGroupMembersCount,
			size_t * pGroupMembersBufferSize,
			int *pGroupMembersBufferIsMalloced,
			char **buffer, size_t * buflen,
			int *depth,
			struct name_list **pKnownGroups) /* traversed groups */
{
  NSS_STATUS stat = NSS_SUCCESS;
  char **dnValues = NULL;
  char **uidValues = NULL;
  char **groupMembers;
  size_t groupMembersCount, i;
  char **valiter;
  /* support for range retrieval */
  const char *uniquemember_attr;
  const char *uniquemember_attrs[2];
  LDAPMessage *res = NULL;
  int start, end = 0;
  char *groupdn = NULL;

  uniquemember_attr = ATM (group, uniqueMember);

  uniquemember_attrs[0] = uniquemember_attr;
  uniquemember_attrs[1] = NULL;

  if (*depth > LDAP_NSS_MAXGR_DEPTH)
    {
      return NSS_NOTFOUND;
    }

  i = *pGroupMembersCount;	/* index of next member */

  groupdn = ldap_get_dn (ld, e);
  if (groupdn == NULL)
    {
      stat = NSS_NOTFOUND;
      goto out;
    }

  if (_nss_ldap_namelist_find (*pKnownGroups, groupdn))
    {
      stat = NSS_NOTFOUND;
      goto out;
    }

  /* store group DN for nested group loop detection */
  stat = _nss_ldap_namelist_push (pKnownGroups, groupdn);
  if (stat != NSS_SUCCESS)
    {
      goto out;
    }

  do
    {
      if (e == NULL)
	{
	  stat = NSS_NOTFOUND;
	  goto out;
	}

      groupMembersCount = 0;	/* number of members in this group */

      (void) do_get_range_values (ld, e, uniquemember_attrs[0], &start, &end, &dnValues);
      if (dnValues != NULL)
	{
	  groupMembersCount += ldap_count_values (dnValues);
	}

      uidValues = ldap_get_values (ld, e, ATM (group, memberUid));
      if (uidValues != NULL)
	{
	  groupMembersCount += ldap_count_values (uidValues);
	}

      /*
       * Check whether we need to increase the group membership buffer.
       * As an optimization the buffer is preferentially allocated off
       * the stack
       */
      if ((i + groupMembersCount) * sizeof (char *) >
	  *pGroupMembersBufferSize)
	{
	  *pGroupMembersBufferSize =
	    (i + groupMembersCount) * sizeof (char *);
	  *pGroupMembersBufferSize +=
	    (LDAP_NSS_MAXGR_BUFSIZ * sizeof (char *)) - 1;
	  *pGroupMembersBufferSize -=
	    (*pGroupMembersBufferSize %
	     (LDAP_NSS_MAXGR_BUFSIZ * sizeof (char *)));

	  if (*pGroupMembersBufferIsMalloced == 0)
	    {
	      groupMembers = *pGroupMembers;
	      *pGroupMembers = NULL;	/* force malloc() */
	    }

	  *pGroupMembers =
	    (char **) realloc (*pGroupMembers, *pGroupMembersBufferSize);
	  if (*pGroupMembers == NULL)
	    {
	      stat = NSS_TRYAGAIN;
	      *pGroupMembersBufferIsMalloced = 0; /* don't try to free */
	      goto out;
	    }

	  if (*pGroupMembersBufferIsMalloced == 0)
	    {
	      memcpy (*pGroupMembers, groupMembers, i * sizeof (char *));
	      groupMembers = NULL;	/* defensive programming */
	      *pGroupMembersBufferIsMalloced = 1;
	    }
	}

      groupMembers = *pGroupMembers;

      /* Parse distinguished name members */
      if (dnValues != NULL)
	{
	  for (valiter = dnValues; *valiter != NULL; valiter++)
	    {
	      LDAPMessage *res;
	      NSS_STATUS parseStat;
	      int isNestedGroup = 0;
	      char *uid;

	      uid = strrchr (*valiter, '#');
	      if (uid != NULL)
		{
		  *uid = '\0';
		}

	      parseStat = _nss_ldap_dn2uid (ld, *valiter, &groupMembers[i],
					    buffer, buflen, &isNestedGroup,
					    &res);
	      if (parseStat == NSS_SUCCESS)
		{
		  if (isNestedGroup == 0)
		    {
		      /* just a normal user which we have flattened */
		      i++;
		      continue;
		    }

		  (*depth)++;
		  parseStat =
		    do_parse_group_members (ld, ldap_first_entry (ld, res),
					    &groupMembers, &i,
					    pGroupMembersBufferSize,
					    pGroupMembersBufferIsMalloced,
					    buffer, buflen, depth,
					    pKnownGroups);
		  (*depth)--;

		  if (parseStat == NSS_TRYAGAIN)
		    {
		      stat = NSS_TRYAGAIN;
		      goto out;
		    }

		  ldap_msgfree (res);
		}
	      else if (parseStat == NSS_TRYAGAIN)
		{
		  stat = NSS_TRYAGAIN;
		  goto out;
		}
	    }
	}

      /* Parse RFC 2307 (flat) members */
      if (uidValues != NULL)
	{
	  for (valiter = uidValues; *valiter != NULL; valiter++)
	    {
	      size_t len = strlen (*valiter) + 1;
	      if (*buflen < len)
		{
		  stat = NSS_TRYAGAIN;
		  goto out;
		}
	      groupMembers[i] = *buffer;
	      *buffer += len;
	      *buflen -= len;

	      memcpy (groupMembers[i++], *valiter, len);
	    }
	}

      /* Get next range for Active Directory compat */
      if (end != -1)
	{
	  stat = do_construct_range_attribute (uniquemember_attr,
					       end + 1,
					       -1,
					       buffer,
					       buflen,
					       &uniquemember_attrs[0]);
	  if (stat == NSS_SUCCESS)
	    {
	      if (dnValues != NULL)
		{
		  ldap_value_free (dnValues);
		  dnValues = NULL;
		}
	      if (uidValues != NULL)
		{
		  ldap_value_free (uidValues);
		  uidValues = NULL;
		}
	      if (res != NULL)
		{
		  ldap_msgfree (res);
		  res = NULL;
		}

	      stat = _nss_ldap_read (groupdn, uniquemember_attrs, &res);
	      if (stat != NSS_SUCCESS)
		goto out;

	      e = ldap_first_entry (ld, res);
	    }
	}
    }
  while (end != -1);

out:
  if (dnValues != NULL)
    ldap_value_free (dnValues);
  if (uidValues != NULL)
    ldap_value_free (uidValues);
  if (res != NULL)
    ldap_msgfree (res);
  if (groupdn != NULL)
#ifdef HAVE_LDAP_MEMFREE
    ldap_memfree (groupdn);
#else
    free (groupdn);
#endif

  *pGroupMembersCount = i;

  return stat;
}

/*
 * "Fix" group membership list into caller provided buffer,
 * and NULL terminate.
*/
static NSS_STATUS
do_fix_group_members_buffer (char **mallocedGroupMembers,
			     size_t groupMembersCount,
			     char ***pGroupMembers,
			     char **buffer, size_t * buflen)
{
  size_t len;

  if (groupMembersCount == 0)
    {
      *pGroupMembers = _nss_ldap_no_members;
      return NSS_SUCCESS;
    }

  len = (groupMembersCount + 1) * sizeof (char *);

  if (bytesleft (*buffer, *buflen, char *) < len)
    {
      return NSS_TRYAGAIN;
    }

  align (*buffer, *buflen, char *);
  *pGroupMembers = (char **) *buffer;
  *buffer += len;
  *buflen -= len;

  memcpy (*pGroupMembers, mallocedGroupMembers,
	  groupMembersCount * sizeof (char *));
  (*pGroupMembers)[groupMembersCount] = NULL;

  return NSS_SUCCESS;
}
#endif /* RFC2307BIS */

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
  char **groupMembers;
  size_t groupMembersCount;
  size_t groupMembersBufferSize;
  char *groupMembersBuffer[LDAP_NSS_MAXGR_BUFSIZ];
  int groupMembersBufferIsMalloced;
  int depth;
  struct name_list *knownGroups = NULL;
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
    _nss_ldap_assign_attrvals (ld, e, ATM (group, memberUid), NULL,
			       &gr->gr_mem, &buffer, &buflen, NULL);
  if (stat != NSS_SUCCESS)
    return stat;
#else
  groupMembers = groupMembersBuffer;
  groupMembersCount = 0;
  groupMembersBufferSize = sizeof (groupMembers);
  groupMembersBufferIsMalloced = 0;
  depth = 0;

  stat = do_parse_group_members (ld, e, &groupMembers, &groupMembersCount,
				 &groupMembersBufferSize,
				 &groupMembersBufferIsMalloced, &buffer,
				 &buflen, &depth, &knownGroups);
  if (stat != NSS_SUCCESS)
    {
      if (groupMembersBufferIsMalloced)
	free (groupMembers);
      _nss_ldap_namelist_destroy (&knownGroups);
      return stat;
    }

  stat = do_fix_group_members_buffer (groupMembers, groupMembersCount,
				      &gr->gr_mem, &buffer, &buflen);

  if (groupMembersBufferIsMalloced)
    free (groupMembers);
  _nss_ldap_namelist_destroy (&knownGroups);

  if (stat != NSS_SUCCESS)
    return stat;
#endif /* RFC2307BIS */

  return NSS_SUCCESS;
}

/*
 * Add a group ID to a group list, and optionally the group IDs
 * of any groups to which this group belongs (RFC2307bis nested
 * group expansion).
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
#ifdef RFC2307BIS
  char *groupdn;
#endif

  values = _nss_ldap_get_values (e, ATM (group, gidNumber));
  if (values == NULL)
    {
      /* invalid group; skip it */
      return NSS_NOTFOUND;
    }

  if (values[0] == NULL)
    {
      ldap_value_free (values);
      return NSS_NOTFOUND;
    }

#ifdef HAVE_USERSEC_H
  i = strlen (values[0]);
  lia->grplist = realloc (lia->grplist, lia->listlen + i + 2);
  if (lia->grplist == NULL)
    {
      ldap_value_free (values);
      return NSS_TRYAGAIN;
    }
  memcpy (lia->grplist + lia->listlen, values[0], i);
  lia->grplist[lia->listlen + i] = ',';
  lia->listlen += i + 1;
  ldap_value_free (values);
#else
  gid = strtoul (values[0], (char **) NULL, 10);
  ldap_value_free (values);

  if (gid == LONG_MAX && errno == ERANGE)
    {
      /* invalid group, skip it */
      return NSS_NOTFOUND;
    }

# ifdef HAVE_NSSWITCH_H
  /* weed out duplicates; is this really our resposibility? */
  for (i = 0; i < lia->gbm->numgids; i++)
    {
      if (lia->gbm->gid_array[i] == (gid_t) gid)
	return NSS_NOTFOUND;
    }

  if (lia->gbm->numgids == lia->gbm->maxgids)
    {
      /* can't fit any more */
      /*
       * should probably return NSS_TRYAGAIN but IIRC
       * will send Solaris into an infinite loop XXX
       */
      return NSS_SUCCESS;
    }

  lia->gbm->gid_array[lia->gbm->numgids++] = (gid_t) gid;
# else
  if (gid == lia->group)
    {
      /* primary group, so skip it */
      return NSS_NOTFOUND;
    }

  if (lia->limit > 0)
    {
      if (*(lia->start) >= lia->limit)
	{
	  /* can't fit any more */
	  return NSS_TRYAGAIN;
	}
    }
  else if (*(lia->start) == *(lia->size))
    {
      /* Need a bigger buffer */
      *(lia->groups) = (gid_t *) realloc (*(lia->groups),
					  2 * *(lia->size) * sizeof (gid_t));
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
	  return NSS_NOTFOUND;
	}
    }

  /* add to group list */
  (*(lia->groups))[*(lia->start)] = gid;
  (*(lia->start)) += 1;
# endif				/* HAVE_NSSWITCH_H */
#endif /* HAVE_USERSEC_H */

#ifdef RFC2307BIS
  /*
   * Now add the GIDs of any groups which refer to this group
   */
  groupdn = ldap_get_dn (ld, e);
  if (groupdn != NULL)
    {
      NSS_STATUS stat;

      lia->depth++;
      stat = ng_chase (ld, groupdn, lia);
      lia->depth--;
#ifdef HAVE_LDAP_MEMFREE
      ldap_memfree (groupdn);
#else
      free (groupdn);
#endif

      return stat;
    }
#endif /* RFC2307BIS */

  return NSS_NOTFOUND;
}

#ifdef RFC2307BIS
static NSS_STATUS
ng_chase (LDAP * ld, const char *dn, ldap_initgroups_args_t * lia)
{
  ldap_args_t a;
  NSS_STATUS stat;
  ent_context_t *ctx = NULL;
  const char *gidnumber_attrs[2];
  int erange;

  if (lia->depth > LDAP_NSS_MAXGR_DEPTH)
    return NSS_NOTFOUND;

  if (_nss_ldap_namelist_find (lia->known_groups, dn))
    return NSS_NOTFOUND;

  LA_INIT (a);

  gidnumber_attrs[0] = ATM (group, gidNumber);
  gidnumber_attrs[1] = NULL;

  LA_INIT (a);
  LA_STRING (a) = dn;
  LA_TYPE (a) = LA_TYPE_STRING;

  if (_nss_ldap_ent_context_init_locked (&ctx) == NULL)
    {
      return NSS_UNAVAIL;
    }

  stat = _nss_ldap_getent_ex (&a, &ctx, lia, NULL, 0,
			      &erange, _nss_ldap_filt_getgroupsbydn,
			      LM_GROUP, gidnumber_attrs, do_parse_initgroups);

  if (stat == NSS_SUCCESS)
    {
      stat = _nss_ldap_namelist_push (&lia->known_groups, dn);
    }

  _nss_ldap_ent_context_release (ctx);
  free (ctx);

  return stat;
}
#endif /* RFC2307BIS */

#if defined(HAVE_NSSWITCH_H) || defined(HAVE_NSS_H) || defined(HAVE_USERSEC_H)
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
#elif defined(HAVE_USERSEC_H)
char *_nss_ldap_getgrset (char *user)
#endif
{
  ldap_initgroups_args_t lia;
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
  static const char *no_attrs[] = { NULL };
  const char *gidnumber_attrs[2];

  LA_INIT (a);
#if defined(HAVE_NSS_H) || defined(HAVE_USERSEC_H)
  LA_STRING (a) = user;
#else
  LA_STRING (a) = ((struct nss_groupsbymem *) args)->username;
#endif /* HAVE_NSS_H || HAVE_USERSEC_H */
  LA_TYPE (a) = LA_TYPE_STRING;

#ifdef HAVE_USERSEC_H
  lia.grplist = NULL;
  lia.listlen = 0;
#elif defined(HAVE_NSSWITCH_H)
  lia.gbm = (struct nss_groupsbymem *) args;
#else
  lia.group = group;
  lia.start = start;
  lia.size = size;
  lia.groups = groupsp;
  lia.limit = limit;
#endif /* HAVE_USERSEC_H */
  lia.depth = 0;
  lia.known_groups = NULL;

  _nss_ldap_enter ();

  /* initialize schema */
  stat = _nss_ldap_init ();
  if (stat != NSS_SUCCESS)
    {
      _nss_ldap_leave ();
# ifdef HAVE_USERSEC_H
      return NULL;
# else
      return stat;
# endif				/* !HAVE_USERSEC_H */
    }

#ifdef RFC2307BIS
  /* lookup the user's DN. */
  stat =
    _nss_ldap_search_s (&a, _nss_ldap_filt_getpwnam, LM_PASSWD, no_attrs, 1,
			&res);
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
# ifdef HAVE_USERSEC_H
      return NULL;
# else
      return NSS_UNAVAIL;
# endif				/* HAVE_USERSEC_H */
    }
#else
  filter = _nss_ldap_filt_getgroupsbymember;
#endif /* RFC2307BIS */

  gidnumber_attrs[0] = ATM (group, gidNumber);
  gidnumber_attrs[1] = NULL;

  stat = _nss_ldap_getent_ex (&a, &ctx, (void *) &lia, NULL, 0,
#ifdef HAVE_NSS_H
			      errnop,
#else
			      &erange,
#endif /* HAVE_NSS_H */
			      filter, LM_GROUP, gidnumber_attrs,
			      do_parse_initgroups);

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

  _nss_ldap_namelist_destroy (&lia.known_groups);
  _nss_ldap_ent_context_release (ctx);
  free (ctx);
  _nss_ldap_leave ();

  /*
   * We return NSS_NOTFOUND to force the parser to be called
   * for as many entries (i.e. groups) as exist, for all
   * search descriptors. So confusingly this means "success".
   */
  if (stat != NSS_SUCCESS && stat != NSS_NOTFOUND)
    {
#ifndef HAVE_NSS_H
      if (erange)
	errno = ERANGE;
#endif /* HAVE_NSS_H */
#ifndef HAVE_USERSEC_H
      return stat;
#else
      return NULL;
#endif /* HAVE_USERSEC_H */
    }

#ifdef HAVE_NSS_H
  return NSS_SUCCESS;
#elif defined(HAVE_USERSEC_H)
  /* Strip last comma and terminate the string */
  if (lia.grplist == NULL)
    lia.grplist = strdup("");
  else if (lia.listlen != 0)
    lia.grplist[lia.listlen - 1] = '\0';

  return lia.grplist;
#else
  /* yes, NSS_NOTFOUND is the successful errno code. see nss_dbdefs.h */
  return NSS_NOTFOUND;
#endif /* HAVE_NSS_H */
}
#endif /* HAVE_NSSWITCH_H || HAVE_NSS_H || HAVE_USERSEC_H */

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
NSS_STATUS _nss_ldap_setgrent (void)
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
NSS_STATUS _nss_ldap_endgrent (void)
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
