/**
 * @file restauth.c REST-based authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <time.h>
#include <re.h>
#include <re_sha.h>
#include <restund.h>


/*
 * This module implements a REST-based authentication mechanism
 * using ephemeral (i.e. time-limited) credentials.
 *
 * A shared secret must be configured in the auth database, and can then
 * be shared with a HTTP REST-based service.
 *
 *
 * Reference:
 *
 *     https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00
 */


static inline int decode_user(time_t *expires, const char **username,
			      const char *user)
{
	time_t e = 0;

	for (;;) {
		const char ch = *user++;

		if (ch >= '0' && ch <= '9') {
			e *= 10;
			e += (ch - '0');
		}
		else if (ch == ':') {
			if (!e)
				return EBADMSG;

			*expires  = e;
			*username = user;

			return 0;
		}
		else {
			return EBADMSG;
		}
	}
}


static int auth_handler(const char *user, uint8_t *ha1)
{
	uint8_t key[MD5_SIZE], digest[SHA_DIGEST_LENGTH];
	const char *username;
	time_t expires, now;
	char pass[28];
	size_t len;
	int err;

	err = decode_user(&expires, &username, user);
	if (err)
		return err;

	now = time(NULL);

	if (expires < now) {
		restund_debug("restauth: user '%s' expired %lli seconds ago\n",
			      user, now - expires);
		return ETIMEDOUT;
	}

	/* avoid recursive loops */
	restund_db_set_auth_handler(NULL);
	err = restund_get_ha1(username, key);
	restund_db_set_auth_handler(auth_handler);
	if (err)
		return err;

	hmac_sha1(key, sizeof(key),
		  (uint8_t *)user, strlen(user),
		  digest, sizeof(digest));

	len = sizeof(pass);
	err = base64_encode(digest, sizeof(digest), pass, &len);
	if (err)
		return err;

	return md5_printf(ha1, "%s:%s:%b", user, restund_realm(), pass, len);
}


static int module_init(void)
{
	restund_db_set_auth_handler(auth_handler);

	restund_debug("restauth: module loaded\n");

	return 0;
}


static int module_close(void)
{
	restund_db_set_auth_handler(NULL);

	restund_debug("restauth: module closed\n");

	return 0;
}


const struct mod_export DECL_EXPORTS(restauth) = {
	.name  = "restauth",
	.type  = "auth",
	.init  = module_init,
	.close = module_close
};
