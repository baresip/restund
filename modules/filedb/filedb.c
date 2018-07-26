/**
 * @file filedb.c File-based Database Backend
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <re.h>
#include <restund.h>


static char filepath[512] = "/etc/restund.auth";


static int user_load(uint32_t *nump, restund_db_account_h *acch, void *arg)
{
	uint32_t num = 0;
	int fd = -1;
	int err = 0;

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		err = errno;
		restund_error("filedb: open '%s': %m\n", filepath, err);
		goto out;
	}

	for (;;) {
		struct pl r, name, ha1, eol;
		uint8_t buf[8192];
		ssize_t n;

		n = read(fd, (void *)buf, sizeof(buf));
		if (n < 0) {
			err = errno;
			restund_error("filedb: read: %m\n", err);
			goto out;
		}
		else if (n == 0)
			break;

		r.p = (char *)buf;
		r.l = n;

		while (!re_regex(r.p, r.l, "[^: \t\r\n]+:[0-9a-f]+[\r\n]+",
				 &name, &ha1, &eol)) {

			char username[256];
			char ha1str[32+1];

			pl_advance(&r, eol.p + eol.l - r.p);

			if (name.l > 0 && name.p[0] == '#')
				continue;

			if (ha1.l != 32) {
				restund_warning("filedb: user %r: bad ha1\n",
						&name);
				continue;
			}

			pl_strcpy(&name, username, sizeof(username));
			pl_strcpy(&ha1, ha1str, sizeof(ha1str));

			++num;

			if (acch)
				acch(username, ha1str, arg);
		}

		if (r.l == (size_t)n || r.l == 0)
			continue;

		if (lseek(fd, -r.l, SEEK_CUR) < 0) {
			err = errno;
			restund_error("filedb: lseek: %m\n", err);
			goto out;
		}
	}

 out:
	if (fd >= 0)
		close(fd);

	if (!err && nump)
		*nump = num;

	return err;
}


static int accounts_getall(const char *realm, restund_db_account_h *acch,
			   void *arg)
{
	if (!realm || !acch)
		return EINVAL;

	return user_load(NULL, acch, arg);
}


static int accounts_count(const char *realm, uint32_t *n)
{
	if (!realm || !n)
		return EINVAL;

	return user_load(n, NULL, NULL);
}


static int module_init(void)
{
	static struct restund_db db = {
		.allh = accounts_getall,
		.cnth = accounts_count,
	};

	restund_db_set_handler(&db);

	conf_get_str(restund_conf(), "filedb_path",
		     filepath, sizeof(filepath));

	restund_debug("filedb: module loaded (%s)\n", filepath);

	return 0;
}


static int module_close(void)
{
	restund_debug("filedb: module closed\n");

	return 0;
}


const struct mod_export DECL_EXPORTS(filedb) = {
	.name = "filedb",
	.type = "file backend",
	.init = module_init,
	.close = module_close,
};
