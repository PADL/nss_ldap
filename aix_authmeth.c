
/*
   Glue code to support AIX loadable authentication modules.

   Note: only information functions are supported, so you need to
   specify "options = dbonly" in /usr/lib/security/methods.cfg
 */
#include "config.h"

#ifdef _AIX

#include <stdlib.h>
#include <string.h>
#include <usersec.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

#include "ldap-nss.h"
#include "ldap-grp.h"
#include "globals.h"
#include "util.h"

static struct irs_gr *grp_conn = NULL;
static struct irs_pw *pwd_conn = NULL;

/* Prototype definitions */
void *gr_pvtinit (void);
struct group *gr_byname (struct irs_gr *, const char *);
struct group *gr_bygid (struct irs_gr *, gid_t);
void gr_close (struct irs_gr *);

void *pw_pvtinit (void);
struct passwd *pw_byname (struct irs_pw *, const char *);
struct passwd *pw_byuid (struct irs_pw *, uid_t);
void pw_close (struct irs_pw *);

char *_nss_ldap_getgrset (char *user);

static void *
_nss_ldap_open (const char *name, const char *domain,
		const int mode, char *options)
{
  /* Currently we do not use the above parameters */

  grp_conn = (struct irs_gr *) gr_pvtinit ();
  pwd_conn = (struct irs_pw *) pw_pvtinit ();
  return NULL;
}

static int
_nss_ldap_close (void *token)
{
  gr_close (grp_conn);
  grp_conn = NULL;

  pw_close (pwd_conn);
  pwd_conn = NULL;

  return 0;
}

static struct group *
_nss_ldap_getgrgid (gid_t gid)
{
  if (!grp_conn)
    return NULL;

  return gr_bygid (grp_conn, gid);
}

static struct group *
_nss_ldap_getgrnam (const char *name)
{
  if (!grp_conn)
    return NULL;

  return gr_byname (grp_conn, name);
}

static struct passwd *
_nss_ldap_getpwuid (uid_t uid)
{
  if (!pwd_conn)
    return NULL;

  return pw_byuid (pwd_conn, uid);
}

static struct passwd *
_nss_ldap_getpwnam (const char *name)
{
  if (!pwd_conn)
    return NULL;

  return pw_byname (pwd_conn, name);
}

static struct group *
_nss_ldap_getgracct (void *id, int type)
{
  if (type == SEC_INT)
    return _nss_ldap_getgrgid (*(gid_t *) id);
  else
    return _nss_ldap_getgrnam ((char *) id);
}

int
nss_ldap_initialize (struct secmethod_table *meths)
{
  bzero (meths, sizeof (*meths));

  /* Identification methods */
  meths->method_getpwnam = _nss_ldap_getpwnam;
  meths->method_getpwuid = _nss_ldap_getpwuid;
  meths->method_getgrnam = _nss_ldap_getgrnam;
  meths->method_getgrgid = _nss_ldap_getgrgid;
  meths->method_getgrset = _nss_ldap_getgrset;
  meths->method_getgracct = _nss_ldap_getgracct;

  /* Support methods */
  meths->method_open = _nss_ldap_open;
  meths->method_close = _nss_ldap_close;

  return 0;
}

#endif /* _AIX */
