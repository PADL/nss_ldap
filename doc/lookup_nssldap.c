#ident "$Id$"
/* ----------------------------------------------------------------------- *
 *
 *  lookup_nss.c - module for Linux automountd to access a NSS
 *		 automount map
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2001-2003 Ian Kent <raven@themaw.net>
 *   Copyright 2005-2006 PADL Software Pty Ltd - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <dlfcn.h>
#include <nss.h>

#define MODULE_LOOKUP
#include "automount.h"

#define MAPFMT_DEFAULT "sun"

#define NAMESERVICE "ldap"

#define MODPREFIX "lookup(nss" NAMESERVICE "): "

struct lookup_context {
	char *nsname;
	char *mapname;
	struct parse_mod *parse;
	void *dlhandle;
	enum nss_status (*setautomntent)(const char *, void **);
	enum nss_status (*getautomntent_r)(void *, const char **, const char **,
					   char *, size_t, int *);
	enum nss_status (*endautomntent)(void **);
	enum nss_status (*getautomntbyname_r)(void *, const char *,
					      const char **, const char **,
					      char *, size_t, int *);
};

int lookup_version = AUTOFS_LOOKUP_VERSION;

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context_p)
{
	struct lookup_context *context;
	char buf[1024];

	context = (struct lookup_context *)malloc(sizeof(*context));
	if (context == NULL) {
		crit(MODPREFIX "malloc: %m");
		return 1;
	}
	memset(context, 0, sizeof(*context));

	context->nsname = NULL;
	context->parse = NULL;
	context->dlhandle = NULL;
	context->setautomntent = NULL;
	context->getautomntent_r = NULL;
	context->endautomntent = NULL;

	if (mapfmt == NULL) {
		mapfmt = MAPFMT_DEFAULT;
	}

	if (argc < 1) {
		crit(MODPREFIX "invalid number of arguments");
		return 1;
	}

	asprintf(&context->nsname, "nss%s", NAMESERVICE);
	if (context->nsname == NULL) {
		crit(MODPREFIX "strdup: %m");
		return 1;
	}

	snprintf(buf, sizeof(buf), "libnss_%s.so.2", NAMESERVICE);

	context->dlhandle = dlopen(buf, RTLD_NOW | RTLD_LOCAL);
	if (context->dlhandle == NULL) {
		crit(MODPREFIX "failed to load %s nameservice provider: %s", NAMESERVICE, dlerror());
		return 1;
	}

	snprintf(buf, sizeof(buf), "_nss_%s_setautomntent", NAMESERVICE);
	context->setautomntent = dlsym(context->dlhandle, buf);
	if (context->setautomntent == NULL) {
		crit(MODPREFIX "failed to load %s nameservice provider: %s", NAMESERVICE, dlerror());
		return 1;
	}

	snprintf(buf, sizeof(buf), "_nss_%s_getautomntent_r", NAMESERVICE);
	context->getautomntent_r = dlsym(context->dlhandle, buf);
	if (context->getautomntent_r == NULL) {
		crit(MODPREFIX "failed to load %s nameservice provider: %s", NAMESERVICE, dlerror());
		return 1;
	}

	snprintf(buf, sizeof(buf), "_nss_%s_endautomntent", NAMESERVICE);
	context->endautomntent = dlsym(context->dlhandle, buf);
	if (context->endautomntent == NULL) {
		crit(MODPREFIX "failed to load %s nameservice provider: %s", NAMESERVICE, dlerror());
		return 1;
	}

	snprintf(buf, sizeof(buf), "_nss_%s_getautomntbyname_r", NAMESERVICE);
	context->getautomntbyname_r = dlsym(context->dlhandle, buf);
	if (context->getautomntbyname_r == NULL) {
		crit(MODPREFIX "failed to load %s nameservice provider: %s", NAMESERVICE, dlerror());
		return 1;
	}

	context->mapname = strdup(argv[0]);
	if (context->mapname == NULL) {
		crit(MODPREFIX "strdup: %m");
		return 1;
	}

	context->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (context->parse == NULL) {
		free(context);
		return 1;
	}

	*context_p = context;
	return 0;
}

static const char *nsserr_string(enum nss_status status)
{
	switch (status) {
	case NSS_STATUS_TRYAGAIN:
		return "Insufficient buffer space";
		break;
	case NSS_STATUS_UNAVAIL:
		return "Name service unavailable";
		break;
	case NSS_STATUS_NOTFOUND:
		return "Not found";
		break;
	case NSS_STATUS_SUCCESS:
		return "Success";
		break;
	default:
		break;
	}

	return "Unknown error";
}

static int read_map(const char *root, time_t age, struct lookup_context *context)
{
	enum nss_status status;
	void *private = NULL;
	const char *key, *mapent;
	int nss_errno;
	char buffer[KEY_MAX_LEN + 1 + MAPENT_MAX_LEN + 1];

	status = (*context->setautomntent)(context->mapname, &private);
	if (status != NSS_STATUS_SUCCESS) {
		warn(MODPREFIX "lookup_ghost for map %s failed: %s",
			context->mapname, nsserr_string(status));
		return 0;
	}

	for (;;) {
		status = (*context->getautomntent_r)(private, &key, &mapent,
						     buffer, sizeof(buffer),
						     &nss_errno);
		if (status != NSS_STATUS_SUCCESS)
			break;

                cache_add(root, key, mapent, age);
	}

	(*context->endautomntent)(&private);

	if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
		warn(MODPREFIX "lookup_ghost for map %s failed: %s",
			context->mapname, nsserr_string(status));
		return 0;
	}

	/* Clean stale entries from the cache */
	cache_clean(root, age);

	return 1;
}

int lookup_ghost(const char *root, int ghost, time_t now, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *)context;
	time_t age = now ? now : time(NULL);
	struct mapent_cache *me;
	int status = 1;

	if (!read_map(root, age, ctxt))
		return LKP_FAIL;

	status = cache_ghost(root, ghost, ctxt->mapname, ctxt->nsname, ctxt->parse);

	me = cache_lookup_first();
	/* me NULL => empty map */
	if (me == NULL)
		return LKP_FAIL;

	if (*me->key == '/' && *(root + 1) != '-') {
		me = cache_partial_match(root);
		/* me NULL => no entries for this direct mount root or indirect map */
		if (me == NULL)
			return LKP_FAIL | LKP_INDIRECT;
	}

	return status;
}

int lookup_one(const char *root, const char *key, time_t age, struct lookup_context *ctxt)
{
	enum nss_status status;
	void *private = NULL;
	int nss_errno;
	char buffer[KEY_MAX_LEN + 1 + MAPENT_MAX_LEN + 1];
	const char *canon_key, *mapent;

	status = (*ctxt->setautomntent)(ctxt->mapname, &private);
	if (status != NSS_STATUS_SUCCESS) {
		warn(MODPREFIX "failed to lookup map %s: %s", ctxt->mapname, nsserr_string(status));
		return CHE_FAIL;
	}

	status = (*ctxt->getautomntbyname_r)(private, key,
					     &canon_key, &mapent,
					     buffer, sizeof(buffer),
					     &nss_errno);

	(*ctxt->endautomntent)(&private);

	if (status == NSS_STATUS_NOTFOUND) {
		warn(MODPREFIX "key %s not found in map %s", key, ctxt->mapname);
		return CHE_MISSING;
	} else if (status != NSS_STATUS_SUCCESS) {
		warn(MODPREFIX "failed to read map %s: %s", ctxt->mapname, nsserr_string(status));
		return CHE_FAIL;
	}

	/* XXX should we be using canon_key or key */
	return cache_update(root, canon_key, mapent, age);
}

int lookup_wild(const char *root, time_t age, struct lookup_context *ctxt)
{
	return lookup_one(root, "*", age, ctxt);
}

int lookup_mount(const char *root, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *)context;
	char key[KEY_MAX_LEN + 1];
	size_t key_len;
	char mapent[MAPENT_MAX_LEN + 1];
	struct mapent_cache *me = NULL;
	int ret;
	time_t now = time(NULL);
	time_t t_last_read;
	int rmdir_if_mount_fails = 0;

	debug(MODPREFIX "looking up %s", name);

	if (ap.type == LKP_DIRECT)
		key_len = snprintf(key, KEY_MAX_LEN, "%s/%s", root, name);
	else
		key_len = snprintf(key, KEY_MAX_LEN, "%s", name);

	if (key_len > KEY_MAX_LEN)
		return 1;

	/* check map and if change is detected re-read map */
	ret = lookup_one(root, key, now, ctxt);
	if (ret == CHE_FAIL)
		return 1;

	me = cache_lookup_first();
	t_last_read = (me != NULL) ? now - me->age : ap.exp_runfreq + 1;

	if (ret == CHE_UPDATED) {
		/* Have parent update its map */
		if (t_last_read > ap.exp_runfreq)
			kill(getppid(), SIGHUP);
	} else if (ret == CHE_MISSING) {
		if (!cache_delete(root, key, 0)) {
			rmdir_if_mount_fails = 1;
		}

		/* Maybe update wild card map entry */
		if (ap.type == LKP_INDIRECT)
			ret = lookup_wild(root, now, ctxt);

		/* Have parent update its map */
		if (t_last_read > ap.exp_runfreq)
			kill(getppid(), SIGHUP);
	}

	me = cache_lookup(key);
	if (me != NULL) {
		snprintf(mapent, sizeof(mapent), "%s", me->mapent);
	} else {	
		/* path component, do submount */
		me = cache_partial_match(key);
		if (me != NULL) {
			snprintf(mapent, sizeof(mapent), "-fstype=autofs %s:%s",
				 ctxt->nsname, ctxt->mapname);
		}
	}

	if (me == NULL)
		return 1;

	debug(MODPREFIX "%s -> %s", name, mapent);

	ret = ctxt->parse->parse_mount(root, name, name_len, mapent, ctxt->parse->context);

	if (ret && rmdir_if_mount_fails)
		rmdir_path(key);

	return ret;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *)context;
	int ret;

	if (ctxt->nsname != NULL) {
		free(ctxt->nsname);
		ctxt->nsname = NULL;
	}

	if (ctxt->mapname != NULL) {
		free(ctxt->mapname);
		ctxt->mapname = NULL;
	}

	ret = close_parse(ctxt->parse);

	if (ctxt->dlhandle != NULL) {
		dlclose(ctxt->dlhandle);
		ctxt->dlhandle = NULL;
	}

	memset(ctxt, 0, sizeof(*ctxt));
	free(ctxt);

	return ret;
}

