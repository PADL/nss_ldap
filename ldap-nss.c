
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
 */

static char rcsId[] =
"$Id$";

#ifdef SUN_NSS
#include <thread.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <lber.h>
#include <ldap.h>
#ifdef SSL
#include <ldap_ssl.h>
#endif /* SSL */

#ifdef GNU_NSS
#include <nss.h>
#elif defined(IRS_NSS)
#include "irs-nss.h"
#elif defined(SUN_NSS)
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#endif

#include "ldap-nss.h"
#include "ltf.h"
#include "globals.h"
#include "util.h"
#ifndef HAVE_SNPRINTF
#include "snprintf.h"
#endif /* HAVE_SNPRINTF */
#include "dnsconfig.h"

/*
 * If things don't link because ldap_ld_free() isn't defined,
 * then try undefining this.
 */
#define HAVE_LDAP_LD_FREE

/*
 * the configuration is read by the first call to do_open().
 * Pointers to elements of the list are passed around but should not
 * be freed.
 */
static char __configbuf[NSS_LDAP_CONFIG_BUFSIZ];
static ldap_config_t *__config = NULL;

/*
 * Global LDAP session.
 */
static ldap_session_t __session =
{NULL, NULL};

/* 
 * Process ID that opened the session.
 */
static pid_t __pid = -1;
static uid_t __euid = -1;

static void do_close (void);
static void do_close_no_unbind (void);
static void do_disable_keepalive (LDAP * ld);
static NSS_STATUS do_open (void);
static NSS_STATUS do_search_s (const char *base, int scope,
			       const char *filter, const char **attrs,
			       int sizelimit, LDAPMessage ** res);

/*
 * Rebind functions.
 */
#if NETSCAPE_API_EXTENSIONS
static int
_nss_ldap_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
		  int freeit, void *arg)
#else
static int
_nss_ldap_rebind (LDAP * ld, char **whop, char **credp, int *methodp,
		  int freeit)
#endif				/* NETSCAPE_API_EXTENSIONS */
{
  if (freeit)
    {
      if (*whop != NULL)
	free (*whop);
      if (*credp != NULL)
	free (*credp);
    }

  if (__session.ls_config->ldc_binddn != NULL)
    *whop = strdup (__session.ls_config->ldc_binddn);
  else
    *whop = NULL;

  if (__session.ls_config->ldc_bindpw != NULL)
    *credp = strdup (__session.ls_config->ldc_bindpw);
  else
    *credp = NULL;

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}

#ifdef SUN_NSS
/*
 * Default destructor.
 * The entry point for this function is the destructor in the dispatch
 * table for the switch. Thus, it's safe to grab the mutex from this
 * function.
 */
NSS_STATUS
_nss_ldap_default_destr (nss_backend_t * be, void *args)
{
  ent_context_t *ctx = ((nss_ldap_backend_t *) be)->state;

  debug ("==> _nss_ldap_default_destr");

  nss_context_lock ();

  if (ctx != NULL)
    {
      if (ctx->ec_res != NULL)
	{
	  ldap_msgfree (ctx->ec_res);
	}
      free (ctx);
      ((nss_ldap_backend_t *) be)->state = NULL;
    }

  /* Ditch the backend. */
  free (be);

  nss_context_unlock ();

  nss_cleanup ();

  debug ("<== _nss_ldap_default_destr");

  return NSS_SUCCESS;
}

/*
 * This is the default "constructor" which gets called from each 
 * constructor, in the NSS dispatch table.
 */
NSS_STATUS
_nss_ldap_default_constr (nss_ldap_backend_t * be)
{
  debug ("==> _nss_ldap_default_constr");

  be->state = NULL;

  debug ("<== _nss_ldap_default_constr");

  return NSS_SUCCESS;
}
#endif /* SUN_NSS */

/*
 * Closes connection to the LDAP server.
 * This assumes that we have exclusive access to __session.ls_conn,
 * either by some other function having acquired a lock, or by
 * using a thread safe libldap.
 */
static void
do_close (void)
{
  debug ("==> do_close");

  if (__session.ls_conn != NULL)
    {
#ifdef DEBUG
      syslog (LOG_DEBUG, "nss_ldap: closing connection %p",
	      __session.ls_conn);
#endif /* DEBUG */
      ldap_unbind (__session.ls_conn);
      __session.ls_conn = NULL;
    }

  debug ("<== do_close");
}

/*
 * If we've forked, then we need to open a new session.
 * Careful: we have the socket shared with our parent,
 * so we don't want to send an unbind to the server.
 * However, we want to close the descriptor to avoid
 * leaking it, and we also want to release the memory
 * used by __session.ls_conn. The only entry point
 * we have is ldap_unbind() which does both of these
 * things, so we use an internal API, at the expense
 * of compatibility.
 */
static void
do_close_no_unbind (void)
{
  debug ("==> do_close_no_unbind");

#ifdef DEBUG
  if (__session.ls_conn != NULL)
    {
      syslog (LOG_DEBUG, "nss_ldap: closing connection (no unbind) %p",
	      __session.ls_conn);
    }
#endif /* DEBUG */

  if (__session.ls_conn != NULL)
    {
#ifdef HAVE_LDAP_LD_FREE
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
      extern int ldap_ld_free (LDAP * ld, int close, LDAPControl **,
			       LDAPControl **);
      (void) ldap_ld_free (__session.ls_conn, 0, NULL, NULL);
#else
      extern int ldap_ld_free (LDAP * ld, int close);
      (void) ldap_ld_free (__session.ls_conn, 0);
#endif /* OPENLDAP 2.x */
#else
      /*
       * We'll be rude and close the socket ourselves. 
       * XXX untested code
       */
      int sd = -1;
#ifdef LDAP_VERSION3_API
      if (ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd) == 0)
#else
      if ((sd = __session.ls_conn->ld_sb.sb_sd) > 0)
#endif /* LDAP_VERSION3_API */
	{
	  close (sd);
	  sd = -1;
#ifdef LDAP_VERSION3_API
	  (void) ldap_set_option (__session.ls_conn, LDAP_OPT_DESC, &sd);
#else
	  __session.ls_conn->ld_sb.sb_sd = sd;
#endif /*  LDAP_VERSION3_API */
	}
	/* hope we closed it OK! */
	ldap_unbind(__session.ls_conn);
#endif /* HAVE_LDAP_LD_FREE */
      __session.ls_conn = NULL;
    }
  debug ("<== do_close_no_unbind");

  return;
}

static INLINE void
do_disable_keepalive (LDAP * ld)
{
  int sd = -1;

  debug ("==> do_disable_keepalive");
#ifdef LDAP_VERSION3_API
  if (ldap_get_option (ld, LDAP_OPT_DESC, &sd) == 0)
#else
  if ((sd = ld->ld_sb.sb_sd) > 0)
#endif /* LDAP_VERSION3_API */
    {
      int off = 0;
      (void) setsockopt (sd, SOL_SOCKET, SO_KEEPALIVE, &off, sizeof off);
    }
  debug ("<== do_disable_keepalive");

  return;
}

/*
 * Opens connection to an LDAP server.
 * As with do_close(), this assumes ownership of sess.
 * It also wants to own __config: is there a potential deadlock here? XXX
 */
static NSS_STATUS
do_open (void)
{
  ldap_config_t *cfg = NULL;
  pid_t pid;
  uid_t euid;

  debug ("==> do_open");

  euid = geteuid ();
  pid = getpid ();

#ifdef DEBUG
  syslog (LOG_DEBUG,
     "nss_ldap: __session.ls_conn=%p, __pid=%i, pid=%i, __euid=%i, euid=%i",
	  __session.ls_conn, __pid, pid, __euid, euid);
#endif /* DEBUG */


  if (__pid != pid)
    {
      do_close_no_unbind ();
    }
  else if (__euid != euid && (__euid == 0 || euid == 0))
    {
      /*
       * If we've changed user ids, close the session so we can
       * rebind as the correct user.
       */
      do_close ();
    }
  else if (__session.ls_conn != NULL && __session.ls_config != NULL)
    {
      /*
       * Otherwise we can hand back this process' global
       * LDAP session.
       */
#ifdef TEST_SERVER_UP /* experimental */
      /*
       * Ensure we save signal handler for sigpipe and restore after
       * LDAP connection is confirmed to be up or a new connection
       * is opened. This prevents Solaris nscd and other apps from
       * dying on a SIGPIPE. I'm not entirely convinced that we
       * ought not to block SIGPIPE elsewhere, but at least this is
       * the entry point where connections get woken up.
       *
       * Also: this may not be necessary now that keepaliave is
       * disabled (the signal code that is). 
       *
       * The W2K client library sends an ICMP echo to the server to
       * check it is up. Perhaps we shold do the same.
       */
      struct sockaddr_in sin;
      int sd = -1;

#ifdef LDAP_VERSION3_API
      if (ldap_get_option (__session.ls_conn, LDAP_OPT_DESC, &sd) == 0)
#else
      if ((sd = __session.ls_conn->ld_sb.sb_sd) > 0)
#endif /* LDAP_VERSION3_API */
	{
	  void (*old_handler) (int sig);
	  int len;

#ifdef SUN_NSS
	  old_handler = sigset (SIGPIPE, SIG_IGN);
#else
	  old_handler = signal (SIGPIPE, SIG_IGN);
#endif /* SUN_NSS */
	  if (getpeername (sd, (struct sockaddr *) &sin, &len) < 0)
	    {
	      /*
	       * The other end has died. Close the connection.
	       */
	      do_close ();
	    }
	  if (old_handler != SIG_ERR && old_handler != SIG_IGN)
	    {
#ifdef SUN_NSS
	      (void) sigset (SIGPIPE, old_handler);
#else
	      (void) signal (SIGPIPE, old_handler);
#endif /* SUN_NSS */
	    }
	}

      /*
       * If the connection is still there (ie. do_close() wasn't
       * called) then we can return the cached connection.
       */
      if (__session.ls_conn != NULL)
	{
	  debug ("<== do_open");
	  return NSS_SUCCESS;
	}
#else
      /*
       * Just return.
       */
      debug ("<== do_open");
      return NSS_SUCCESS;
#endif /* TEST_SERVER_UP */
    }

  __pid = pid;
  __euid = euid;
  __session.ls_config = NULL;

  if (__config == NULL)
    {
      NSS_STATUS status;

      status =
	_nss_ldap_readconfig (&__config, __configbuf, sizeof (__configbuf));

      if (status != NSS_SUCCESS)
	{
	  status =
	    _nss_ldap_readconfigfromdns (&__config, __configbuf,
					 sizeof (__configbuf));
	}

      if (status != NSS_SUCCESS)
	{
	  __config = NULL;
	  debug ("<== do_open");
	  return status;
	}
    }

  cfg = __config;

  while (1)
    {
#ifdef SSL
      /*
       * Initialize the SSL library. Should be one-time, but 
       * things could change between config files.
       */
      if (cfg->ldc_ssl_on)
	{
	  if (ldapssl_client_init (cfg->ldc_sslpath, NULL) != LDAP_SUCCESS)
	    {
	      continue;
	    }
	}
#endif /* SSL */

#ifdef LDAP_VERSION3_API
      debug ("==> ldap_init");
      __session.ls_conn = ldap_init (cfg->ldc_host, cfg->ldc_port);
      debug ("<== ldap_init");
#else
      debug ("==> ldap_open");
      __session.ls_conn = ldap_open (cfg->ldc_host, cfg->ldc_port);
      debug ("<== ldap_open");
#endif /* LDAP_VERSION3_API */
      if (__session.ls_conn != NULL || cfg->ldc_next == cfg)
	{
	  break;
	}
      cfg = cfg->ldc_next;
    }

  if (__session.ls_conn == NULL)
    {
      debug ("<== do_open");
      return NSS_UNAVAIL;
    }

#ifdef NETSCAPE_API_EXTENSIONS
  if (_nss_ldap_ltf_thread_init (__session.ls_conn) != NSS_SUCCESS)
    {
      do_close ();
      debug ("<== do_open");
      return NSS_UNAVAIL;
    }
#endif /* NETSCAPE_API_EXTENSIONS */

#ifdef NETSCAPE_API_EXTENSIONS
  ldap_set_rebind_proc (__session.ls_conn, _nss_ldap_rebind, NULL);
#else
  ldap_set_rebind_proc (__session.ls_conn, _nss_ldap_rebind);
#endif /* NETSCAPE_API_EXTENSIONS */

#ifdef LDAP_VERSION3_API
  ldap_set_option (__session.ls_conn, LDAP_OPT_PROTOCOL_VERSION,
		   &cfg->ldc_version);
#else
  __session.ls_conn->ld_version = cfg->ldc_version;
#endif /* LDAP_VERSION3_API */

#ifdef SSL
  /*
   * If SSL is desired, then enable it.
   */
  if (cfg->ldc_ssl_on)
    {
      if (ldapssl_install_routines (__session.ls_conn) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
      if (ldap_set_option (__session.ls_conn, LDAP_OPT_SSL, LDAP_OPT_ON) !=
	  LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }
#endif /* SSL */

  /*
   * If we're running as root, let us bind as a special
   * user, so we can fake shadow passwords.
   * Thanks to Doug Nazar <nazard@dragoninc.on.ca> for this
   * patch.
   */
  if (euid == 0 && cfg->ldc_rootbinddn != NULL)
    {
      if (ldap_simple_bind_s
	  (__session.ls_conn, cfg->ldc_rootbinddn,
	   cfg->ldc_rootbindpw) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }
  else
    {
      if (ldap_simple_bind_s
	  (__session.ls_conn, cfg->ldc_binddn,
	   cfg->ldc_bindpw) != LDAP_SUCCESS)
	{
	  do_close ();
	  debug ("<== do_open");
	  return NSS_UNAVAIL;
	}
    }

  /*
   * Disable SO_KEEPALIVE on the session's socket.
   */
  do_disable_keepalive (__session.ls_conn);

  __session.ls_config = cfg;

  debug ("<== do_open");

  return NSS_SUCCESS;
}

/*
 * This function initializes an enumeration context.
 * It is called from setXXent() directly, and so can safely lock the
 * mutex. 
 *
 * It could be done from the default constructor, under Solaris, but we
 * delay it until the setXXent() function is called.
 */
ent_context_t *
_nss_ldap_ent_context_init (context_handle_t * key)
{
  ent_context_t *ctx;

  debug ("==> _nss_ldap_ent_context_init");

  nss_context_lock ();

  ctx = *key;

  if (ctx == NULL)
    {
      ctx = (ent_context_t *) malloc (sizeof (*ctx));
      if (ctx == NULL)
	{
	  nss_context_unlock ();
	  debug ("<== _nss_ldap_ent_context_init");
	  return NULL;
	}
      ctx->ec_res = NULL;
      *key = ctx;
    }
  else if (ctx->ec_res != NULL)
    {
      ldap_msgfree (ctx->ec_res);
    }

  ctx->ec_res = NULL;
  ctx->ec_last = NULL;
  LS_INIT (ctx->ec_state);

  nss_context_unlock ();

  debug ("<== _nss_ldap_ent_context_init");
  return ctx;
}

/*
 * Frees a given context; this is called from endXXent() and so we
 * can grab the lock.
 */
void
_nss_ldap_ent_context_free (context_handle_t * key)
{
  ent_context_t *ctx = *key;

  debug ("==> _nss_ldap_ent_context_free");

  nss_context_lock ();

  if (ctx == NULL)
    {
      nss_context_unlock ();
      debug ("<== _nss_ldap_ent_context_free");
      return;
    }

  if (ctx->ec_res != NULL)
    {
      ldap_msgfree (ctx->ec_res);
    }

  ctx->ec_res = NULL;
  ctx->ec_last = NULL;
  LS_INIT (ctx->ec_state);

  nss_context_unlock ();

  debug ("<== _nss_ldap_ent_context_free");

  return;
}

static NSS_STATUS
do_search_s (const char *base, int scope,
	     const char *filter, const char **attrs, int sizelimit,
	     LDAPMessage ** res)
{
  int lstatus = LDAP_UNAVAILABLE, tries = 0, backoff = 0;
  NSS_STATUS nstatus = NSS_TRYAGAIN;

  debug ("==> do_search_s");

  while (nstatus == NSS_TRYAGAIN &&
	 tries < LDAP_NSS_MAXCONNTRIES + LDAP_NSS_TRIES)
    {
      if (tries > LDAP_NSS_MAXCONNTRIES)
	{
	  if (backoff == 0)
	    backoff = LDAP_NSS_SLEEPTIME;
	  else if (backoff < LDAP_NSS_MAXSLEEPTIME)
	    backoff *= 2;

	  syslog (LOG_INFO,
	   "nss_ldap: reconnecting to LDAP server (sleeping %d seconds)...",
		  backoff);
	  (void) sleep (backoff);
	}
      else if (tries > 0)
	{
	  /* Don't sleep, reconnect immediately. */
	  syslog (LOG_INFO, "nss_ldap: reconnecting to LDAP server...");
	}

      if (do_open () != NSS_SUCCESS)
	{
	  __session.ls_conn = NULL;
	  ++tries;
	  continue;
	}

#ifdef LDAP_VERSION3_API
      ldap_set_option (__session.ls_conn, LDAP_OPT_SIZELIMIT,
		       (void *) &sizelimit);
#else
      __session.ls_conn->ld_sizelimit = sizelimit;
#endif /* LDAP_VERSION3_API */

      lstatus = ldap_search_s (__session.ls_conn, base, scope, filter,
			       (char **) attrs, 0, res);

      switch (lstatus)
	{
	case LDAP_SUCCESS:
	case LDAP_SIZELIMIT_EXCEEDED:
	case LDAP_TIMELIMIT_EXCEEDED:
	  nstatus = NSS_SUCCESS;
	  break;
	case LDAP_SERVER_DOWN:
	case LDAP_TIMEOUT:
	case LDAP_UNAVAILABLE:
	case LDAP_BUSY:
	  do_close ();
	  nstatus = NSS_TRYAGAIN;
	  ++tries;
	  continue;
	  break;
	default:
	  nstatus = NSS_UNAVAIL;
	  break;
	}
    }

  switch (nstatus)
    {
    case NSS_UNAVAIL:
      syslog (LOG_ERR, "nss_ldap: could not search LDAP server - %s",
	      ldap_err2string (lstatus));
      break;
    case NSS_TRYAGAIN:
      syslog (LOG_ERR, "nss_ldap: could not reconnect to LDAP server - %s",
	      ldap_err2string (lstatus));
      nstatus = NSS_UNAVAIL;
      break;
    case NSS_SUCCESS:
      if (tries)
	syslog (LOG_ERR,
		"nss_ldap: reconnected to LDAP server after %d attempt(s)",
		tries);
      break;
    default:
      break;
    }

  debug ("<== do_search_s");

  return nstatus;
}

NSS_STATUS
_nss_ldap_read (const char *dn, const char **attributes, LDAPMessage ** res)
{
  return do_search_s (dn, LDAP_SCOPE_BASE, "(objectclass=*)", attributes, 1,	/* sizelimit */
		      res);
}

char **
_nss_ldap_get_values (LDAPMessage * e, char *attr)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_get_values (__session.ls_conn, e, attr);
}

char *
_nss_ldap_get_dn (LDAPMessage * e)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_get_dn (__session.ls_conn, e);
}

LDAPMessage *
_nss_ldap_first_entry (LDAPMessage * res)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_first_entry (__session.ls_conn, res);
}

LDAPMessage *
_nss_ldap_next_entry (LDAPMessage * res)
{
  if (__session.ls_conn == NULL)
    {
      return NULL;
    }
  return ldap_next_entry (__session.ls_conn, res);
}

/*
 * The generic lookup cover function.
 * Assumes caller holds lock.
 */
NSS_STATUS
_nss_ldap_lookup (const ldap_args_t * args,
		  const char *filterprot, const char **attrs, int sizelimit,
		  LDAPMessage ** res)
{
  char filter[LDAP_FILT_MAXSIZ + 1];
  NSS_STATUS stat;

  debug ("==> _nss_ldap_lookup");

  stat = do_open ();
  if (stat != NSS_SUCCESS)
    {
      __session.ls_conn = NULL;
      debug ("<== _nss_ldap_lookup");
      return stat;
    }

  if (args != NULL)
    {
      switch (args->la_type)
	{
	case LA_TYPE_STRING:
#ifdef HAVE_SNPRINTF
	  snprintf (filter, sizeof (filter), filterprot,
		    args->la_arg1.la_string);
#else
	  sprintf (filter, filterprot, args->la_arg1.la_string);
#endif
	  break;
	case LA_TYPE_NUMBER:
#ifdef HAVE_SNPRINTF
	  snprintf (filter, sizeof (filter), filterprot,
		    args->la_arg1.la_number);
#else
	  sprintf (filter, filterprot, args->la_arg1.la_number);
#endif
	  break;
	case LA_TYPE_STRING_AND_STRING:
#ifdef HAVE_SNPRINTF
	  snprintf (filter, sizeof (filter), filterprot,
		    args->la_arg1.la_string, args->la_arg2.la_string);
#else
	  sprintf (filter, filterprot, args->la_arg1.la_string,
		   args->la_arg2.la_string);
#endif
	  break;
	case LA_TYPE_NUMBER_AND_STRING:
#ifdef HAVE_SNPRINTF
	  snprintf (filter, sizeof (filter), filterprot,
		    args->la_arg1.la_number, args->la_arg2.la_string);
#else
	  sprintf (filter, filterprot, args->la_arg1.la_number,
		   args->la_arg2.la_string);
#endif
	  break;
	}
    }

  stat = do_search_s (__session.ls_config->ldc_base,
		      __session.ls_config->ldc_scope,
		      (args == NULL) ? (char *) filterprot : filter,
		      attrs, sizelimit, res);

  debug ("<== _nss_ldap_lookup");

  return stat;
}

/*
 * General entry point for enumeration routines.
 * This should really use the asynchronous LDAP search API to avoid
 * pulling down all the entries at once, particularly if the
 * enumeration is not completed.
 * Locks mutex.
 */
NSS_STATUS
_nss_ldap_getent (ent_context_t * ctx,
		  void *result,
		  char *buffer,
		  size_t buflen,
		  int *errnop,
		const char *filterprot, const char **attrs, parser_t parser)
{
  NSS_STATUS stat = NSS_NOTFOUND;

  if (ctx == NULL)
    {
      return NSS_UNAVAIL;
    }

  /*
   * we need to lock here as the context may not be thread-specific
   * data (under glibc, for example). Maybe we should make the lock part
   * of the context.
   */

  nss_context_lock ();

  /*
   * if ec_state.ls_info.ls_index is non-zero, then we don't collect another
   * entry off the LDAP chain, and instead refeed the existing result to
   * the parser. Once the parser has finished with it, it will return
   * NSS_NOTFOUND and reset the index to -1, at which point we'll retrieve
   * another entry.
   */
  if (ctx->ec_res == NULL)
    {
      LDAPMessage *res;

      stat = _nss_ldap_lookup (NULL, filterprot, attrs, LDAP_NO_LIMIT, &res);
      if (stat != NSS_SUCCESS)
	{
	  nss_context_unlock ();
	  return stat;
	}
      stat = NSS_NOTFOUND;

      ctx->ec_res = res;
      ctx->ec_last = ldap_first_entry (__session.ls_conn, ctx->ec_res);
    }
  else
    {
      if (ctx->ec_state.ls_info.ls_index == -1)
	{
	  ctx->ec_last = ldap_next_entry (__session.ls_conn, ctx->ec_last);
	}
    }

  while (ctx->ec_last != NULL)
    {
      stat =
	parser (__session.ls_conn, ctx->ec_last, &ctx->ec_state, result,
		buffer, buflen);
      if (stat == NSS_SUCCESS)
	{
	  break;
	}
      if (ctx->ec_state.ls_info.ls_index == -1)
	{
	  ctx->ec_last = ldap_next_entry (__session.ls_conn, ctx->ec_last);
	}
    }

  if (ctx->ec_last == NULL)
    {
      ldap_msgfree (ctx->ec_res);
      ctx->ec_res = NULL;
    }

  nss_context_unlock ();

  if (stat == NSS_TRYAGAIN)
    {
#ifdef SUN_NSS
      errno = ERANGE;
      *errnop = 1;		/* this is really erange */
#else
      *errnop = ERANGE;
#endif /* SUN_NSS */
    }
  return stat;
}

/*
 * General match function.
 * Locks mutex.
 */
NSS_STATUS
_nss_ldap_getbyname (ldap_args_t * args,
		     void *result,
		     char *buffer,
		     size_t buflen,
		     int *errnop,
		     const char *filterprot,
		     const char **attrs, parser_t parser)
{
  LDAPMessage *res;
  LDAPMessage *e;
  NSS_STATUS stat = NSS_NOTFOUND;
  ldap_state_t state;

  nss_context_lock ();

  stat = _nss_ldap_lookup (args, filterprot, attrs, 1, &res);
  if (stat != NSS_SUCCESS)
    {
      nss_context_unlock ();
      return stat;
    }

  /*
   * Reset stat. Otherwise we might just return NSS_SUCCESS
   * for no entries which could be a huge security hole.
   */
  stat = NSS_NOTFOUND;

  /*
   * we pass this along for the benefit of the services parser,
   * which uses it to figure out which protocol we really wanted.
   * we only pass the second argument along, as that's what we need
   * in services.
   */
  state.ls_type = LS_TYPE_KEY;
  state.ls_info.ls_key = args->la_arg2.la_string;

  for (e = ldap_first_entry (__session.ls_conn, res);
       e != NULL; e = ldap_next_entry (__session.ls_conn, e))
    {
      stat = parser (__session.ls_conn, e, &state, result, buffer, buflen);
      if (stat == NSS_SUCCESS)
	break;
    }

  ldap_msgfree (res);

  nss_context_unlock ();

  if (stat == NSS_TRYAGAIN)
    {
#ifdef SUN_NSS
      errno = ERANGE;
      *errnop = 1;		/* this is really erange */
#else
      *errnop = ERANGE;
#endif /* SUN_NSS */
    }

  return stat;
}

/*
 * These functions are called from within the parser, where it is assumed
 * to be safe to use the connection and the respective message.
 */

/*
 * Assign all values, bar omitvalue (if not NULL), to *valptr.
 */
NSS_STATUS
_nss_ldap_assign_attrvals (LDAP * ld,
			   LDAPMessage * e,
			   const char *attr,
			   const char *omitvalue,
			   char ***valptr,
			   char **pbuffer,
			   size_t * pbuflen, size_t * pvalcount)
{
  char **vals;
  char **valiter;
  int valcount;
  char **p = NULL;

  register int buflen = *pbuflen;
  register char *buffer = *pbuffer;

  if (pvalcount != NULL)
    {
      *pvalcount = 0;
    }

  vals = ldap_get_values (ld, e, (char *) attr);

  valcount = (vals == NULL) ? 0 : ldap_count_values (vals);
  if (bytesleft (buffer, buflen) < (valcount + 1) * sizeof (char *))
    {
      ldap_value_free (vals);
      return NSS_TRYAGAIN;
    }

  align (buffer, buflen);
  p = *valptr = (char **) buffer;

  buffer += (valcount + 1) * sizeof (char *);
  buflen -= (valcount + 1) * sizeof (char *);

  if (valcount == 0)
    {
      *p = NULL;
      *pbuffer = buffer;
      *pbuflen = buflen;
      return NSS_SUCCESS;
    }

  valiter = vals;

  while (*valiter != NULL)
    {
      int vallen;
      char *elt = NULL;

      if (omitvalue != NULL && strcmp (*valiter, omitvalue) == 0)
	{
	  valcount--;
	}
      else
	{
	  vallen = strlen (*valiter);
	  if (buflen < (size_t) (vallen + 1))
	    {
	      ldap_value_free (vals);
	      return NSS_TRYAGAIN;
	    }

	  /* copy this value into the next block of buffer space */
	  elt = buffer;
	  buffer += vallen + 1;
	  buflen -= vallen + 1;

	  strncpy (elt, *valiter, vallen);
	  elt[vallen] = '\0';
	  *p = elt;
	  p++;
	}
      valiter++;
    }

  *p = NULL;
  *pbuffer = buffer;
  *pbuflen = buflen;

  if (pvalcount != NULL)
    {
      *pvalcount = valcount;
    }

  ldap_value_free (vals);
  return NSS_SUCCESS;
}

/* Assign a single value to *valptr. */
NSS_STATUS
_nss_ldap_assign_attrval (LDAP * ld,
			  LDAPMessage * e,
			  const char *attr,
			  char **valptr, char **buffer, size_t * buflen)
{
  char **vals;
  int vallen;

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals == NULL)
    {
      return NSS_NOTFOUND;
    }

  vallen = strlen (*vals);
  if (*buflen < (size_t) (vallen + 1))
    {
      ldap_value_free (vals);
      return NSS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, *vals, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  ldap_value_free (vals);

  return NSS_SUCCESS;
}


/*
 * Assign a single value to *valptr, after examining userPassword for
 * a syntactically suitable value. The behaviour here is determinable at
 * runtime from ldap.conf.
 */
NSS_STATUS
_nss_ldap_assign_passwd (LDAP * ld,
			 LDAPMessage * e,
			 const char *attr,
			 char **valptr, char **buffer, size_t * buflen)
{
  char **vals;
  char **valiter;
  char *pwd = NULL;
  int vallen;

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals != NULL)
    {
      for (valiter = vals; *valiter != NULL; valiter++)
	{
	  if (strncasecmp (*valiter,
			   "{CRYPT}",
			   (sizeof("{CRYPT}") - 1)) == 0)
	    {
	      pwd = *valiter;
	      break;
	    }
	}
    }

  if (pwd == NULL)
    {
      pwd = "x";
    }
  else
    {
      pwd += (sizeof("{CRYPT}") - 1);
    }

  vallen = strlen (pwd);

  if (*buflen < (size_t) (vallen + 1))
    {
      if (vals != NULL)
	{
	  ldap_value_free (vals);
	}
      return NSS_TRYAGAIN;
    }

  *valptr = *buffer;

  strncpy (*valptr, pwd, vallen);
  (*valptr)[vallen] = '\0';

  *buffer += vallen + 1;
  *buflen -= vallen + 1;

  if (vals != NULL)
    {
      ldap_value_free (vals);
    }

  return NSS_SUCCESS;
}
