#include <memory.h>
#include <re.h>


#include "restund.h"
#include "turn.h"

#include "federate.h"

#define	LAYER_DTLS 20       /* must be above zero */

struct tconn {
	struct federate *fed;
	struct tls_conn *tc;
	struct sa peer;
	bool estab;

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
	
	restund_info("federate_dtls(%p): tconn=%p established with: %J\n",
		     fed, tconn, &tconn->peer);

	tconn->estab = true;
	le = tconn->sendl.head;
	while(le) {
		struct send_entry *se = le->data;

		le = le->next;
		dtls_send(tconn->tc, se->mb);

		mem_deref(se);
	}
}

static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct tconn *tconn = arg;
	struct federate *fed = tconn ? tconn->fed : NULL;

	restund_debug("federate_dtls(%p): dtls_recv_handler: on tconn=%p "
		      "nbytes=%zu\n",
		      fed, tconn, mbuf_get_left(mb));

	if (!fed)
		return;

	federate_recv(fed, mb);	
}

static void dtls_close_handler(int err, void *arg)
{
	struct tconn *tconn = arg;
	struct federate *fed = tconn ? tconn->fed : NULL;

	restund_debug("federate_dtls(%p): dtls_close_handler: on tconn=%p "
		      "err=%m\n",
		      fed, tconn, err);

	mem_deref(tconn);
}


static void tconn_destructor(void *arg)
{
	struct tconn *tconn = arg;

	list_unlink(&tconn->le);

	list_flush(&tconn->sendl);
	tconn->fed = mem_deref(tconn->fed);
}

static struct tconn *alloc_tconn(struct federate *fed, const struct sa *peer)
{
	struct tconn *tconn;
	
	tconn = mem_zalloc(sizeof(*tconn), tconn_destructor);
	if (tconn) {
		sa_cpy(&tconn->peer, peer);		
		tconn->fed = mem_ref(fed);
		list_append(&fed->dtls.connl, &tconn->le, tconn);
	}

	return tconn;
}

static void dtls_conn_handler(const struct sa *peer, void *arg)
{
	struct federate *fed = arg;
	struct tconn *tconn = NULL;
	int err;

	restund_debug("federate_dtls(%p): incoming DTLS connect peer=%J\n",
		      fed, peer);

	tconn = alloc_tconn(fed, peer);
	if (!tconn) {
		restund_warning("federate_dtls(%p): cannot alloc tconn\n", fed);
		return;
	}
	
	err = dtls_accept(&tconn->tc,
			  fed->dtls.tls,
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
	
	restund_debug("federate_tls(%p): dtls accepted tls_conn=%p\n",
		      fed, tconn->tc);

 out:
	if (err)
		mem_deref(tconn);
	//crypto_error(rf, err);
}


int federate_dtls_init(struct federate *fed, struct sa *lsa)
{
	int err;

	if (!fed || !lsa)
		return EINVAL;
	
	err = tls_alloc(&fed->dtls.tls, TLS_METHOD_DTLS, NULL, NULL);
	if (err) {
		restund_debug("reflow: failed to create DTLS context (%m)\n",
			err);
		goto out;
	}

	err = cert_enable_ecdh(fed->dtls.tls);
	if (err)
		goto out;

	restund_debug("turn: setting %zu ciphers for DTLS\n",
		      ARRAY_SIZE(cipherv));
	err = tls_set_ciphers(fed->dtls.tls, cipherv, ARRAY_SIZE(cipherv));
	if (err)
		goto out;

	restund_debug("turn: generating ECDSA certificate\n");
	err = cert_tls_set_selfsigned_ecdsa(fed->dtls.tls, "prime256v1");
	if (err) {
		restund_debug("federate_dtls: failed to generate ECDSA"
			      " certificate"
			      " (%m)\n", err);
		goto out;
	}

	tls_set_verify_client(fed->dtls.tls);

	err = tls_set_srtp(fed->dtls.tls,
			   "SRTP_AEAD_AES_256_GCM:"
			   "SRTP_AEAD_AES_128_GCM:"
			   "SRTP_AES128_CM_SHA1_80");
	if (err) {
		restund_debug("turn: failed to enable SRTP profile (%m)\n",
			      err);
		goto out;
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
	fed->dtls.tls = mem_deref(fed->dtls.tls);	
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

int federate_dtls_send(struct federate *fed, const struct sa *dst,
		       struct mbuf *mb)
{
	struct tconn *tconn = NULL;
	int err = 0;
	
	if (!fed && fed->type != FED_TYPE_DTLS)
		return EINVAL;

	restund_debug("federate_dtls_send(%p): send to: %J\n", fed, dst);
	
	tconn = lookup_tconn(fed, dst);
	if (tconn && tconn->estab) {
		restund_debug("federate_dtls_send(%p): direct send\n", fed);
		err = dtls_send(tconn->tc, mb);
		goto out;
	}
	if (!tconn) {
		tconn = alloc_tconn(fed, dst);
		if (!tconn)
			return ENOMEM;

		restund_debug("federate_dtls_send(%p): allocating tconn: %p "
			      "dst=%J\n",
			      fed, tconn, dst);
		
		err = dtls_connect(&tconn->tc, fed->dtls.tls,
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

		restund_debug("federate_dtls_send(%p): queueing packet of size: %zu\n", fed, mbuf_get_left(mb));
		list_append(&tconn->sendl, &se->le, se);

		return 0;
	}

 out:
	if (err)
		mem_deref(tconn);

	return err;
}
