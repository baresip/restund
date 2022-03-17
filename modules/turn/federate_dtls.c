#include <memory.h>
#include <re.h>


#include "restund.h"
#include "turn.h"

#include "federate.h"


#define	LAYER_DTLS 20       /* must be above zero */

#define TIMEOUT_CONN   2000

#undef PACKET_DEBUG

struct tconn {
	struct federate *fed;
	struct tls *tls;
	struct tls_conn *tc;
	struct sa peer;
	bool estab;

	struct tmr tmr_conn;
	struct list sendl; /* send_entry of packets to send upon connection */
	struct le le; /* member of federate connl */
};

struct send_entry {
	struct mbuf *mb;
	
	struct le le;
};

static const char *cipherv[] = {

	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"DHE-RSA-AES128-GCM-SHA256",
	"DHE-DSS-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-SHA256",
	"ECDHE-ECDSA-AES128-SHA256",
	"ECDHE-RSA-AES128-SHA",
	"ECDHE-ECDSA-AES128-SHA",
	"ECDHE-RSA-AES256-SHA384",
	"ECDHE-ECDSA-AES256-SHA384",
	"ECDHE-RSA-AES256-SHA",
	"ECDHE-ECDSA-AES256-SHA",
	"DHE-RSA-AES128-SHA256",
	"DHE-RSA-AES128-SHA",
	"DHE-DSS-AES128-SHA256",
	"DHE-RSA-AES256-SHA256",
	"DHE-DSS-AES256-SHA",
	"DHE-RSA-AES256-SHA",
	"ECDHE-RSA-AES128-CBC-SHA",

};


static void dtls_estab_handler(void *arg)
{
	struct tconn *tconn = arg;
	struct federate *fed = tconn ? tconn->fed : NULL;
	struct le *le;
	char cn[256] = "";
	int err;
	
	restund_info("federate_dtls(%p): tconn=%p established with: %J\n",
		     fed, tconn, &tconn->peer);

	err = tls_peer_common_name(tconn->tc, cn, sizeof(cn));
	restund_info("in estab: CN=%s(%m)\n", err ? "???" : cn, err);
	tmr_cancel(&tconn->tmr_conn);
	
	tconn->estab = true;
	le = tconn->sendl.head;
	
	mem_ref(tconn);
	while(le) {
		struct send_entry *se = le->data;

		le = le->next;
		dtls_send(tconn->tc, se->mb);

		mem_deref(se);
	}
	mem_deref(tconn);
}

static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct tconn *tconn = arg;
	struct federate *fed = tconn ? tconn->fed : NULL;

#ifdef PACKET_DEBUG
	restund_info("federate_dtls(%p): dtls_recv_handler: on tconn=%p "
		     "nbytes=%zu\n",
		     fed, tconn, mbuf_get_left(mb));
#endif
	
	if (!fed)
		return;

	federate_recv(fed, mb);	
}

static void dtls_close_handler(int err, void *arg)
{
	struct tconn *tconn = arg;
	struct federate *fed = tconn ? tconn->fed : NULL;

	restund_info("federate_dtls(%p): dtls_close_handler: on tconn=%p "
		     "err=%m\n",
		     fed, tconn, err);

	mem_deref(tconn);
}


static void tconn_destructor(void *arg)
{
	struct tconn *tconn = arg;	

	tmr_cancel(&tconn->tmr_conn);
	tconn->tc = mem_deref(tconn->tc);
	list_unlink(&tconn->le);

	list_flush(&tconn->sendl);

	tconn->tls = mem_deref(tconn->tls);
	tconn->fed = mem_deref(tconn->fed);
}

int alloc_tls(struct tls **tlsp, struct federate *fed, bool isclient)
{
	struct tls *tls;
	int err;
	
	err = tls_alloc(&tls, TLS_METHOD_DTLSV1_2,
			fed->dtls.certfile, fed->dtls.passwd);
	if (err) {
		restund_info("reflow: failed to create DTLS context (%m)\n",
			err);
		goto out;
	}

	if (fed->dtls.certfile) {
		cert_setup_file(tls, (int)fed->dtls.depth, isclient);
	}
	else {
		restund_info("turn: generating ECDSA certificate\n");
		err = cert_tls_set_selfsigned_ecdsa(tls,
						    "prime256v1");
		if (err) {
			restund_info("federate_dtls: failed to generate ECDSA"
				     " certificate"
				     " (%m)\n", err);
			goto out;
		}
	}
	
	if (fed->dtls.cafile) {
		err = tls_add_ca(tls, fed->dtls.cafile);
		if (err) {
			restund_warning("federate_dtls: failed CA: %s(%m)\n",
					fed->dtls.cafile, err);
			goto out;
		}
	}

	err = cert_enable_ecdh(tls);
	if (err)
		goto out;

	restund_info("turn: setting %zu ciphers for DTLS\n",
		      ARRAY_SIZE(cipherv));
	err = tls_set_ciphers(tls, cipherv, ARRAY_SIZE(cipherv));
	if (err)
		goto out;

	//tls_set_verify_client(fed->dtls.tls);

#if 0
	err = tls_set_srtp(fed->dtls.tls,
			   "SRTP_AEAD_AES_256_GCM:"
			   "SRTP_AEAD_AES_128_GCM:"
			   "SRTP_AES128_CM_SHA1_80");
	if (err) {
		restund_info("turn: failed to enable SRTP profile (%m)\n",
			      err);
		goto out;
	}
#endif

 out:
	if (err)
		mem_deref(tls);
	else if (tlsp)
		*tlsp = tls;

	return err;
}


static struct tconn *alloc_tconn(struct federate *fed,
				 const struct sa *peer,
				 bool isclient)
{
	struct tconn *tconn;
	int err = 0;
	
	tconn = mem_zalloc(sizeof(*tconn), tconn_destructor);
	if (tconn) {
		sa_cpy(&tconn->peer, peer);		
		tconn->fed = mem_ref(fed);
		list_append(&fed->dtls.connl, &tconn->le, tconn);
	}

	err = alloc_tls(&tconn->tls, fed, isclient);
	if (err) {
		restund_warning("federate_dtls(%p): alloc tls failed: %m\n",
				fed, err);
		goto out;
	}
	
 out:

	if (err) {
		mem_deref(tconn);
		tconn = NULL;
	}
       

	return tconn;
}

static void dtls_conn_handler(const struct sa *peer, void *arg)
{
	struct federate *fed = arg;
	struct tconn *tconn = NULL;
	int err;

	restund_info("federate_dtls(%p): incoming DTLS connect peer=%J\n",
		     fed, peer);

	tconn = alloc_tconn(fed, peer, false);
	if (!tconn) {
		restund_warning("federate_dtls(%p): cannot alloc tconn\n", fed);
		return;
	}
	
	err = dtls_accept(&tconn->tc,
			  tconn->tls,
			  fed->dtls.sock,
			  dtls_estab_handler,
			  dtls_recv_handler,
			  dtls_close_handler,
			  tconn);
	if (err) {
		restund_warning("federate_dtls(%p): accept failed (%m)\n",
				fed, err);
		goto out;
	}

#if 0
	err = tls_peer_verify(tconn->tc);
	restund_info("federate_dtls(%p): tls verify: %d\n", fed, err);
	{
		char cn[256] = "";
		err = tls_peer_common_name(tconn->tc, cn, sizeof(cn));
		restund_info("federate_dtls(%p): err=%d(%m) CN=%s\n", fed, err, err, cn);
		err = 0;
		
	}
#endif
	
	restund_debug("federate_dtls(%p): dtls accepted tls_conn=%p\n",
		      fed, tconn->tc);

 out:
	if (err)
		mem_deref(tconn);
	//crypto_error(rf, err);
}


int federate_dtls_init(struct federate *fed, struct sa *lsa)
{
	struct pl opt;
	uint32_t depth;
	int err;

	if (!fed || !lsa)
		return EINVAL;

	err = conf_get(restund_conf(), "federate_certfile", &opt);
	if (!err) {
		pl_strdup(&fed->dtls.certfile, &opt);
		restund_info("turn: using cert file: %s\n",
			     fed->dtls.certfile);
	}
	err = conf_get(restund_conf(), "federate_password", &opt);
	if (!err) {
		pl_strdup(&fed->dtls.passwd, &opt);
		restund_info("turn: password protected cert\n");
	}
	err = conf_get(restund_conf(), "federate_cafile", &opt);
	if (!err) {
		pl_strdup(&fed->dtls.cafile, &opt);
		restund_info("turn: using CA file: %s\n",
			     fed->dtls.cafile);
	}
	err = conf_get_u32(restund_conf(), "federate_cert_depth", &depth);
	if (err)
		fed->dtls.depth = 9;
	else {
		fed->dtls.depth = depth;
	}

	err = dtls_listen(&fed->dtls.sock, lsa,
			  NULL, 2, LAYER_DTLS,
			  dtls_conn_handler, fed);

out:
	
	return err;
	
}

void federate_dtls_close(struct federate *fed, int err)
{
	if (!fed)
		return;

	fed->err = err;

	list_flush(&fed->dtls.connl);
	fed->dtls.sock = mem_deref(fed->dtls.sock);

	fed->dtls.cafile = mem_deref(fed->dtls.cafile);
	fed->dtls.certfile = mem_deref(fed->dtls.certfile);
	fed->dtls.passwd = mem_deref(fed->dtls.passwd);
}

static struct tconn *lookup_tconn(struct federate *fed, const struct sa *peer)
{
	struct le *le;
	bool found = false;
	struct tconn *tconn = NULL;	

	le = fed->dtls.connl.head;
	while(le && !found) {
		tconn = le->data;		
		le = le->next;
		found = sa_cmp(peer, &tconn->peer, SA_ALL);
	}

	return found ? tconn : NULL;
}

static void se_destructor(void *arg)
{
	struct send_entry *se = arg;

	list_unlink(&se->le);
	mem_deref(se->mb);	
}

static void conn_timeout_handler(void *arg)
{
	struct tconn *tconn = arg;

	restund_warning("tconn(%p): timeout\n", tconn);

	mem_deref(tconn);
}

int federate_dtls_send(struct federate *fed, const struct sa *dst,
		       struct mbuf *mb)
{
	struct tconn *tconn = NULL;
	int err = 0;
	
	if (!fed)
		return EINVAL;
	if (fed->type != FED_TYPE_DTLS)
		return EINVAL;

	tconn = lookup_tconn(fed, dst);
	
	if (tconn && tconn->estab) {
#ifdef PACKET_DEBUG
		restund_info("federate_dtls_send(%p): direct send: %J\n",
			     fed, dst);
#endif
		err = dtls_send(tconn->tc, mb);
		goto out;
	}
	if (!tconn) {
		tconn = alloc_tconn(fed, dst, true);
		if (!tconn)
			return ENOMEM;

		
		err = dtls_connect(&tconn->tc, tconn->tls,
				   fed->dtls.sock, dst,
				   dtls_estab_handler,
				   dtls_recv_handler,
				   dtls_close_handler,
				   tconn);
		if (err) {
			restund_warning("federate_dtls(%p): connect "
					"failed: %m\n",
					fed, err);
			goto out;
		}
		tmr_start(&tconn->tmr_conn, TIMEOUT_CONN,
			  conn_timeout_handler, tconn);
	}		
	if (tconn) {
		struct send_entry *se;

		se = mem_zalloc(sizeof(*se), se_destructor);
		if (!se) {
			err = ENOMEM;
			goto out;
		}
		se->mb = mbuf_alloc(mb->size);
		if (!se->mb) {
			err = ENOMEM;
			goto out;
		}
		memcpy(se->mb->buf, mb->buf, mb->end);
		se->mb->pos = mb->pos;
		se->mb->end = mb->end;

#ifdef PACKET_DEBUG
		restund_info("federate_dtls_send(%p): "
			     "queueing packet of size: %zu to: %J\n",
			     fed, mbuf_get_left(mb), dst);
#endif

		list_append(&tconn->sendl, &se->le, se);

		return 0;
	}

 out:
	if (err)
		mem_deref(tconn);

	return err;
}
