#include <re.h>

#include "restund.h"
#include "turn.h"

struct federate {
	struct udp_sock *usock;
	struct list allocl;
};

struct tconn {
	struct tls_conn *tc;
	struct sa peer;
	
	struct le le; /* member in connl */
};

static struct fed_alloc *lookup_fal_byalloc(struct federate *fed,
					    struct allocation *al)
{
	bool found = false;
	struct le *le;
	struct fed_alloc *fal;

	le = fed->allocl.head;
	while(le && !found) {
		fal = le->data;
		le = le->next;
		
		found = fal->al == al;
	}

	return found ? fal : NULL;	
}

static struct fed_alloc *lookup_fal(struct federate *fed, uint16_t cid)
{
	bool found = false;
	struct le *le;
	struct fed_alloc *fal;

	le = fed->allocl.head;
	while(le && !found) {
		fal = le->data;
		le = le->next;
		
		found = fal->cid == cid;
	}

	return found ? fal : NULL;	
}


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct federate *fed = arg;
	struct fed_alloc *fal;
	uint16_t chan;
	uint16_t len;
	
	restund_debug("federate(%p): udp_recv_handler: %zubytes from %J\n",
		      fed, mbuf_get_left(mb), src);

	pos = mb->pos;
	chan = ntohs(mbuf_read_u16(mb));
	len = ntohs(mbuf_read_u16(mb));

	fal = lookup_fal(fed, chan);
	if (fal)
		allocate_recv(fal->al, mb, NULL, NULL);
	else {
		restund_debug("federate(%p): no allocation chan: %u\n",
			      fed, chan);
	}
}

static void udp_err_handler(int err, void *arg)
{
	struct federate *fed = arg;
	
	restund_warning("federate: udp(%p) err=%m\n", fed->usock, err);

	mem_deref(fed);
}


static void tconn_destructor(void *arg)
{
	struct tconn *tconn = arg;

	list_unlink(&tconn->le);
	mem_deref(tconn->tc);
	
	mem_deref(tconn->turnd);
}

static fed_destructor(void *arg)
{
	struct federate *fed = arg;

	mem_deref(fed->usock);
	list_flush(&fed->allocl);
}


int federate_alloc(struct federate **fedp, struct sa *local_addr)
{
	struct federate *fed = NULL;
	int err;

	fed = mem_zalloc(sizeof(*fed), fed_desructor);
	if (!fed)
		return ENOMEM;
	
	err = udp_listen(&fed->usock, local_addr,
			 udp_recv_handler, fed);
	udp_error_handler_set(fed->usock, udp_err_handler, fed);

out:
	if (err)
		mem_deref(fed);
	else if (fedp)
		*fedp = fed;
	
	return err;
}


uint16_t federate_add_alloc(struct federation *fed, struct allocation *alx)
{
	struct fed_alloc *fal;

	if (!fed)
		return 0;

	fal = lookup_fal_byalloc(fed, alx);
	if (fal)
		return fal->cid;
	
	fal = mem_zalloc(sizeof(*fal), fal_destructor);
	if (!fal)
		return 0;

	fal->al = alx;

	do {
		struct fed_alloc *fx;

		fal->cid = rand_u16();
		/* Ensure umber is unique, by looking it up */
		if (fal->cid) {			
			fx = lookup_fal(fed, fal->cid):
			if (fx)
				fal->cid = 0;
		}
	} while(fal->cid == 0);

	list_append(&fed->allocl, &fal->le, fal);

	return fal->cid;
}


int federate_send(struct fed *fed, struct sa *dst, struct mbuf *mb)
{
	if (!fed)
		return EINVAL;

	err = udp_send(fed->usock, dst, mb);

	return err;
}
