/**
 * @file dtls.c DTLS Transport (RFC 7350)
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <restund.h>
#include "stund.h"


#ifdef USE_DTLS


enum {
	DTLS_IDLE_TIMEOUT   = 600 * 1000,
	DTLS_HASH_SIZE      = 512,
	DTLS_LAYER          = 0
};

struct dtls_param {
	uint32_t sockbuf_size;
	uint32_t hash_size;
};

struct dtls_lstnr {
	struct le le;
	struct sa bnd_addr;
	struct tls *tls;
	struct dtls_sock *ds;
};

struct conn {
	struct le le;
	struct tmr tmr;
	struct sa laddr;
	struct sa paddr;
	struct tls_conn *tlsc;
	time_t created;
	uint64_t prev_rxc;
	uint64_t rxc;
};


static struct list lstnrl;
static struct list connl;


static void conn_destructor(void *arg)
{
	struct conn *conn = arg;

	list_unlink(&conn->le);
	tmr_cancel(&conn->tmr);
	dtls_set_handlers(conn->tlsc, NULL, NULL, NULL, NULL);
	mem_deref(conn->tlsc);
}


static void tmr_handler(void *arg)
{
	struct conn *conn = arg;

	if (conn->rxc == conn->prev_rxc) {
		restund_debug("dtls: closing idle connection: %J\n",
			      &conn->paddr);
		mem_deref(conn);
		return;
	}

	conn->prev_rxc = conn->rxc;

	tmr_start(&conn->tmr, DTLS_IDLE_TIMEOUT, tmr_handler, conn);
}


static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct conn *conn = arg;

	restund_process_msg(STUN_TRANSP_DTLS, conn->tlsc, &conn->paddr,
			    &conn->laddr, mb);

	++conn->rxc;
}


static void dtls_close_handler(int err, void *arg)
{
	struct conn *conn = arg;

	restund_debug("dtls: connection closed: %m\n", err);

	mem_deref(conn);
}


static void dtls_conn_handler(const struct sa *peer, void *arg)
{
	const time_t now = time(NULL);
	struct dtls_lstnr *dl = arg;
	struct conn *conn;
	int err;

	restund_debug("dtls: connect from: %J\n", peer);

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn) {
		err = ENOMEM;
		goto out;
	}

	list_append(&connl, &conn->le, conn);
	conn->created = now;
	conn->paddr   = *peer;
	conn->laddr   = dl->bnd_addr;

	err = dtls_accept(&conn->tlsc, dl->tls, dl->ds, NULL,
			  dtls_recv_handler, dtls_close_handler, conn);
	if (err)
		goto out;

	tmr_start(&conn->tmr, DTLS_IDLE_TIMEOUT, tmr_handler, conn);

 out:
	if (err) {
		restund_warning("dtls: unable to accept: %m\n", err);
		mem_deref(conn);
	}
}


static void status_handler(struct mbuf *mb)
{
	const time_t now = time(NULL);
	struct le *le;

	for (le=connl.head; le; le=le->next) {

		const struct conn *conn = le->data;

		(void)mbuf_printf(mb, "%J - %J %llis\n",
                                  &conn->laddr, &conn->paddr,
                                  now - conn->created);
	}
}


static void lstnr_destructor(void *arg)
{
	struct dtls_lstnr *dl = arg;

	list_unlink(&dl->le);
	mem_deref(dl->ds);
	mem_deref(dl->tls);
}


static int dtls_listen_handler(const struct pl *val, void *arg)
{
	struct dtls_param *prm = arg;
	struct dtls_lstnr *dl = NULL;
	struct pl ap, cert;
	char certpath[1024];
	int err = ENOMEM;

	dl = mem_zalloc(sizeof(*dl), lstnr_destructor);
	if (!dl) {
		restund_warning("dtls listen error: %m\n", err);
		goto out;
	}

	list_append(&lstnrl, &dl->le, dl);

	if (re_regex(val->p, val->l, "[^,]+,[^]+", &ap, &cert)) {
		restund_warning("bad dtls_listen directive: '%r'\n", val);
		err = EINVAL;
		goto out;
	}

	(void)pl_strcpy(&cert, certpath, sizeof(certpath));

	err = tls_alloc(&dl->tls, TLS_METHOD_DTLSV1, certpath, NULL);
	if (err) {
		restund_warning("tls error: %m\n", err);
		goto out;
	}

	err = sa_decode(&dl->bnd_addr, ap.p, ap.l);
	if (err || sa_is_any(&dl->bnd_addr) || !sa_port(&dl->bnd_addr)) {
		restund_warning("bad dtls_listen address directive: '%r'\n",
				val);
		err = EINVAL;
		goto out;
	}

	err = dtls_listen(&dl->ds, &dl->bnd_addr, NULL, prm->hash_size,
			  DTLS_LAYER, dtls_conn_handler, dl);
	if (err) {
		restund_warning("dtls listen %J: %m\n", &dl->bnd_addr, err);
		goto out;
	}

	if (prm->sockbuf_size > 0)
		(void)udp_sockbuf_set(dtls_udp_sock(dl->ds),
				      prm->sockbuf_size);

	restund_debug("dtls listen: %J\n", &dl->bnd_addr);

 out:
	if (err)
		mem_deref(dl);

	return err;
}


static struct restund_cmdsub cmd_dtls = {
	.cmdh = status_handler,
	.cmd  = "dtls",
};


int restund_dtls_init(void)
{
	struct dtls_param prm;
	int err;

	list_init(&lstnrl);
	list_init(&connl);

	restund_cmd_subscribe(&cmd_dtls);

	prm.sockbuf_size = 0;
	prm.hash_size = DTLS_HASH_SIZE;

	(void)conf_get_u32(restund_conf(), "dtls_sockbuf_size",
			   &prm.sockbuf_size);
	(void)conf_get_u32(restund_conf(), "dtls_hash_size", &prm.hash_size);

	err = conf_apply(restund_conf(), "dtls_listen", dtls_listen_handler,
			 &prm);
	if (err)
		goto out;

 out:
	if (err)
		restund_dtls_close();

	return err;
}


void restund_dtls_close(void)
{
	restund_cmd_unsubscribe(&cmd_dtls);

	list_flush(&lstnrl);
	list_flush(&connl);
}


struct dtls_sock *restund_dtls_socket(struct sa *sa, const struct sa *orig,
				      bool ch_ip, bool ch_port)
{
	struct le *le = list_head(&lstnrl);

	while (le) {
		struct dtls_lstnr *dl = le->data;
		le = le->next;

		if (ch_ip && sa_cmp(orig, &dl->bnd_addr, SA_ADDR))
			continue;

		if (ch_port && (sa_port(orig) == sa_port(&dl->bnd_addr)))
			continue;

		sa_cpy(sa, &dl->bnd_addr);
		return dl->ds;
	}

	return NULL;
}


#else


int restund_dtls_init(void)
{
	return 0;
}


void restund_dtls_close(void)
{
}


struct dtls_sock *restund_dtls_socket(struct sa *sa, const struct sa *orig,
				      bool ch_ip, bool ch_port)
{
	(void)sa;
	(void)orig;
	(void)ch_ip;
	(void)ch_port;

	return NULL;
}


#endif
