/* Copyright (C) 2004 Luke Howard.
   This file is part of the nss_ldap library.
   Contributed by Luke Howard, <lukeh@padl.com>, 2004.

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

#ifdef HAVE_IRS_H

#include <errno.h>
#include "irs-nss.h"

/* $Id$ */

#ifdef HAVE_USERSEC_H
void *ng_pvtinit (void);
#endif
IRS_EXPORT void ng_close (struct irs_ng *);
IRS_EXPORT int ng_next (struct irs_ng *, char **, char **, char **);
IRS_EXPORT int ng_test (struct irs_ng *, const char *, const char *, const char *, const char *);
IRS_EXPORT void ng_rewind (struct irs_ng *, const char *);
IRS_EXPORT void ng_minimize (struct irs_ng *);

IRS_EXPORT int
ng_test (struct irs_ng *this,
	 const char *name, const char *host,
	 const char *user, const char *domain)
{
  NSS_STATUS parseStat;
  ldap_innetgr_args_t li_args;
                                                                                                                             
  li_args.lia_netgroup = name;
  li_args.lia_netgr_status = NSS_NETGR_NO;
  li_args.lia_depth = 0;
  li_args.lia_erange = 0;

  /* fall through to NSS implementation */
  parseStat = do_innetgr (&li_args, host, user, domain);
  if (parseStat != NSS_SUCCESS && parseStat != NSS_NOTFOUND)
    {
      if (li_args.lia_erange)
	errno = ERANGE;
      return 0;
    }

  return (li_args.lia_netgr_status == NSS_NETGR_FOUND);
}

IRS_EXPORT void
ng_rewind (struct irs_ng *this, const char *group)
{
  nss_ldap_netgr_backend_t *ngbe;
  ldap_args_t a;
  NSS_STATUS stat;

  ngbe = (nss_ldap_netgr_backend_t *)this->private;

  /* clear out old state */
  nn_destroy (&ngbe->known_groups);
  nn_destroy (&ngbe->needed_groups);

  LA_INIT (a);
  LA_TYPE (a) = LA_TYPE_STRING;
  LA_STRING (a) = group;

  if (_nss_ldap_ent_context_init (&ngbe->state) == NULL)
    return;

  _nss_ldap_enter ();
  stat = _nss_ldap_search_s (&a, _nss_ldap_filt_getgrent,
			     LM_NETGROUP, NULL, 1,
			     &ngbe->state->ec_res);  

  if (stat == NSS_SUCCESS)
    nn_push (&ngbe->known_groups, group);

  if (stat != NSS_SUCCESS)
    _nss_ldap_ent_context_release (ngbe->state);

  _nss_ldap_leave ();
}

/*
 * This code is essentially the same as that for the
 * nsswitch implementation in ldap-netgrp.c
 */
IRS_EXPORT int
ng_next (struct irs_ng *this, char **host, char **user, char **domain)
{
  nss_ldap_netgr_backend_t *ngbe;
  NSS_STATUS parseStat = NSS_NOTFOUND;
  ent_context_t *ctx;
  char *buffer;
  size_t buflen;

  ngbe = (nss_ldap_netgr_backend_t *)this->private;

  ctx = ngbe->state;
  if (ctx == NULL)
      return 0;

  buffer = ngbe->buffer;
  buflen = NSS_BUFLEN_NETGROUP;  

  do
    {
      NSS_STATUS resultStat = NSS_SUCCESS;
      char **vals, **p;
      ldap_state_t *state = &ctx->ec_state;
      struct __netgrent __netgrent;
      LDAPMessage *e;

      if (state->ls_retry == 0 && state->ls_info.ls_index == -1)
	{
	  resultStat = NSS_NOTFOUND;

	  if (ctx->ec_res != NULL)
	    {
	      e = _nss_ldap_first_entry (ctx->ec_res);
	      if (e != NULL)
		resultStat = NSS_SUCCESS;
	    }

	  if (resultStat != NSS_SUCCESS)
	    {
	      /* chase nested netgroups */
	      resultStat = nn_chase (ngbe, &e);
	    }

	  if (resultStat != NSS_SUCCESS)
	    {
	      parseStat = resultStat;
	      break;
	    }

	  assert (e != NULL);

	  /* Push nested netgroups onto stack for deferred chasing */
	  vals = _nss_ldap_get_values (e, AT (memberNisNetgroup));
	  if (vals != NULL)
	    {
	      for (p = vals; *p != NULL; p++)
		{
		  parseStat = nn_push (&ngbe->needed_groups, *p);
		  if (parseStat != NSS_SUCCESS)
		    break;
		}
	      ldap_value_free (vals);

	      if (parseStat != NSS_SUCCESS)
		break;		/* out of memory */
	    }
	}
      else
	{
	  assert (ctx->ec_res != NULL);
	  e = _nss_ldap_first_entry (ctx->ec_res);
	  if (e == NULL)
	    {
	      /* This should never happen, but we fail gracefully. */
	      parseStat = NSS_UNAVAIL;
	      break;
	    }
	}

      /* We have an entry; now, try to parse it. */
      vals = _nss_ldap_get_values (e, AT (nisNetgroupTriple));
      if (vals == NULL)
	{
	  state->ls_info.ls_index = -1;
	  parseStat = NSS_NOTFOUND;
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	  continue;
	}

      switch (state->ls_info.ls_index)
	{
	case 0:
	  /* last time. decrementing ls_index to -1 AND returning
	   * an error code will force this entry to be discared.
	   */
	  parseStat = NSS_NOTFOUND;
	  break;
	case -1:
	  /* first time */
	  state->ls_info.ls_index = ldap_count_values (vals);
	  /* fall off to default... */
	default:
	  __netgrent.data = vals[state->ls_info.ls_index - 1];
	  __netgrent.data_size = strlen (vals[state->ls_info.ls_index - 1]);
	  __netgrent.cursor = __netgrent.data;
	  __netgrent.first = 1;

	  parseStat = _nss_ldap_parse_netgr (&__netgrent, buffer, buflen);
	  if (parseStat != NSS_SUCCESS)
	    {
	      break;
	    }
	  if (__netgrent.type != triple_val)
	    {
	      parseStat = NSS_NOTFOUND;
	      break;
	    }
	  *host = (char *) __netgrent.val.triple.host;
	  *user = (char *) __netgrent.val.triple.user;
	  *domain = (char *) __netgrent.val.triple.domain;
	  break;
	}

      ldap_value_free (vals);
      state->ls_info.ls_index--;

      /* hold onto the state if we're out of memory XXX */
      state->ls_retry = (parseStat == NSS_TRYAGAIN ? 1 : 0);

      if (state->ls_retry == 0 && state->ls_info.ls_index == -1)
	{
	  ldap_msgfree (ctx->ec_res);
	  ctx->ec_res = NULL;
	}
    }
  while (parseStat == NSS_NOTFOUND);

  if (parseStat == NSS_TRYAGAIN)
    {
      errno = ERANGE;
    }

  return (parseStat == NSS_SUCCESS) ? 1 : 0;
}

IRS_EXPORT void
ng_minimize (struct irs_ng *this)
{
}

IRS_EXPORT void
ng_close (struct irs_ng *this)
{
#ifdef HAVE_USERSEC_H
  nss_ldap_netgr_backend_t *ngbe;

  ngbe = (nss_ldap_netgr_backend_t *)this->private;
  if (ngbe != NULL)
    {
      if (ngbe->state != NULL)
	{
	  _nss_ldap_enter ();
	  _nss_ldap_ent_context_release (ngbe->state);
	  free (ngbe->state);
	  _nss_ldap_leave ();
	}

      nn_destroy (&ngbe->known_groups);
      nn_destroy (&ngbe->needed_groups);

      free (ngbe);
    }

  free (this);
#endif
}

#ifdef HAVE_USERSEC_H
void *
ng_pvtinit (void)
#else
struct irs_ng *
irs_ldap_ng (struct irs_acc *this)
#endif
{
  struct irs_ng *ng;
  nss_ldap_netgr_backend_t *pvt;

  ng = calloc (1, sizeof (*ng));
  if (ng == NULL)
    return NULL;

  pvt = calloc (1, sizeof (*pvt));
  if (pvt == NULL)
    return NULL;

  pvt->state = NULL;
  ng->private = pvt;
  ng->close = ng_close;
  ng->next = ng_next;
  ng->test = ng_test;
  ng->rewind = ng_rewind;
  ng->minimize = ng_minimize;
  return ng;
}

#endif /*HAVE_IRS_H */
