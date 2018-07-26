/**
 * @file main.c  STUN Server
 *
 * Copyright (C) 2010 Creytiv.com
 */

#ifdef SOLARIS
#define __EXTENSIONS__ 1
#endif
#ifdef HAVE_GETOPT
#include <getopt.h>
#endif
#include <pthread.h>
#include <re.h>
#include <restund.h>
#include "stund.h"


static const char *configfile = "/etc/restund.conf";
static struct conf *conf;
static bool force_debug;


static void reload_handler(struct mbuf *mb)
{
	bool dbg = force_debug;
	struct conf *lconf;
	struct pl opt;
	int err;
	(void)mb;

	err = conf_alloc(&lconf, configfile);
	if (err) {
		restund_error("error loading configuration: %s: %m\n",
			      configfile, err);
		return;
	}

	conf = mem_deref(conf);
	conf = lconf;

	if (!conf_get(conf, "debug", &opt) && !pl_strcasecmp(&opt, "yes"))
		dbg = true;

	restund_log_enable_debug(dbg);

	restund_info("configuration reloaded from %s (debug%s)\n",
		     configfile, dbg ? " enabled" : " disabled");
}


static struct restund_cmdsub cmd_reload = {
	.le   = LE_INIT,
	.cmdh = reload_handler,
	.cmd  = "reload",
};


static void signal_handler(int sig)
{
	restund_info("caught signal %d\n", sig);

	re_cancel();
}


#ifdef STATIC

extern const struct mod_export *mod_table[];


static const struct mod_export *find_module(const struct pl *name)
{
	uint32_t i;

	for (i=0; mod_table[i]; i++) {

		if (0 == pl_strcasecmp(name, mod_table[i]->name))
			return mod_table[i];
	}

	return NULL;
}


static int module_handler(const struct pl *pl, void *arg)
{
	const struct mod_export *me;
	struct pl name;
	struct mod *m;
	int err;

	(void)arg;

	if (re_regex(pl->p, pl->l, "[^/.]+.[^]*", &name, NULL))
		return EINVAL;

	me = find_module(&name);
	if (!me) {
		restund_error("can't find module %r\n", &name);
		return ENOENT;
	}

	err = mod_add(&m, me);
	if (err) {
		restund_error("can't add module %r: %m\n", &name, err);
		return err;
	}

	return 0;
}

#else

static int module_handler(const struct pl *val, void *arg)
{
	struct pl *modpath = arg;
	char filepath[256];
	struct mod *mod;
	int err;

	if (val->p && val->l && (*val->p == '/'))
		(void)re_snprintf(filepath, sizeof(filepath), "%r", val);
	else
		(void)re_snprintf(filepath, sizeof(filepath), "%r/%r",
				  modpath, val);

	err = mod_load(&mod, filepath);
	if (err) {
		restund_warning("can't load module %s (%m)\n",
				filepath, err);
		goto out;
	}

 out:
	return err;
}

#endif


struct conf *restund_conf(void)
{
	return conf;
}


#ifdef HAVE_GETOPT
static void usage(void)
{
	(void)re_fprintf(stderr, "usage: restund [-dhn] [-f <file>]\n");
	(void)re_fprintf(stderr, "\t-d         Turn on debugging\n");
	(void)re_fprintf(stderr, "\t-h         Show summary of options\n");
	(void)re_fprintf(stderr, "\t-n         Run in foreground\n");
	(void)re_fprintf(stderr, "\t-f <file>  Configuration file\n");
}
#endif


int main(int argc, char *argv[])
{
	bool daemon = true;
	int err = 0;
	struct pl opt;

	(void)sys_coredump_set(true);

#ifdef HAVE_GETOPT
	for (;;) {

		const int c = getopt(argc, argv, "dhnf:");
		if (0 > c)
			break;

		switch (c) {

		case 'd':
			force_debug = true;
			restund_log_enable_debug(true);
			break;

		case 'f':
			configfile = optarg;
			break;

		case 'n':
			daemon = false;
			break;

		case '?':
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}
#else
	(void)argc;
	(void)argv;
#endif

	restund_cmd_subscribe(&cmd_reload);

	err = fd_setsize(1024);
	if (err) {
		restund_warning("fd_setsize error: %m\n", err);
		goto out;
	}

	err = libre_init();
	if (err) {
		restund_error("re init failed: %m\n", err);
		goto out;
	}

	/* configuration file */
	err = conf_alloc(&conf, configfile);
	if (err) {
		restund_error("error loading configuration: %s: %m\n",
			      configfile, err);
		goto out;
	}

	/* debug config */
	if (!conf_get(conf, "debug", &opt) && !pl_strcasecmp(&opt, "yes"))
		restund_log_enable_debug(true);

	/* udp */
	err = restund_udp_init();
	if (err)
		goto out;

	/* tcp */
	err = restund_tcp_init();
	if (err)
		goto out;

	/* dtls */
	err = restund_dtls_init();
	if (err)
		goto out;

	/* daemon config */
	if (!conf_get(conf, "daemon", &opt) && !pl_strcasecmp(&opt, "no"))
		daemon = false;

	/* module config */
	if (conf_get(conf, "module_path", &opt))
		pl_set_str(&opt, ".");

	err = conf_apply(conf, "module", module_handler, &opt);
	if (err)
		goto out;

	/* daemon */
	if (daemon) {
		err = sys_daemon();
		if (err) {
			restund_error("daemon error: %m\n", err);
			goto out;
 		}

		restund_log_enable_stderr(false);
	}

	/* database */
	err = restund_db_init();
	if (err) {
		restund_warning("database error: %m\n", err);
		goto out;
	}

	restund_info("stun server ready\n");

	/* main loop */
	err = re_main(signal_handler);

 out:
	restund_db_close();
	mod_close();
	restund_udp_close();
	restund_tcp_close();
	restund_dtls_close();
	conf = mem_deref(conf);

	libre_close();

	restund_cmd_unsubscribe(&cmd_reload);

	/* check for memory leaks */
	tmr_debug();
	mem_debug();

	return err;
}
