#include <re.h>

#include "restund.h"
#include "turn.h"

#include "federate.h"


struct fed_conn *federate_lookup_fconn_byalloc(struct federate *fed,
					       struct allocation *al)
{
	bool found = false;
	struct le *le;
	struct fed_conn *fconn;

	le = fed->allocl.head;
	while(le && !found) {
		fconn = le->data;
		le = le->next;
		
		found = fconn->al == al;
	}

	return found ? fconn : NULL;	
}

static struct fed_conn *lookup_fconn(struct federate *fed, uint16_t cid)
{
	struct fed_conn *fconn;
	bool found = false;
	struct le *le;

	le = fed->allocl.head;
	while(le && !found) {
		fconn = le->data;
		le = le->next;
		
		found = fconn->cid == cid;
	}

	return found ? fconn : NULL;	
}

static void fconn_destructor(void *arg)
{
	struct fed_conn *fconn = arg;

	list_unlink(&fconn->le);
}

uint16_t federate_add_conn(struct federate *fed, struct allocation *alx)
{
	struct fed_conn *fconn;

	if (!fed)
		return 0;

	fconn = federate_lookup_fconn_byalloc(fed, alx);
	if (fconn)
		return fconn->cid;
	
	fconn = mem_zalloc(sizeof(*fconn), fconn_destructor);
	if (!fconn)
		return 0;

	fconn->al = alx;

	do {
		fconn->cid = rand_u16();
		/* Ensure cid is unique, by looking it up */
		if (fconn->cid) {			
			if (lookup_fconn(fed, fconn->cid))
				fconn->cid = 0;
		}
	} while(fconn->cid == 0);

	restund_info("federate(%p): adding al(%p) at cid=%u\n",
		     fed, alx, fconn->cid);
	
	list_append(&fed->allocl, &fconn->le, fconn);

	return fconn->cid;
}

int federate_del_conn(struct federate *fed, uint16_t cid)
{
	struct fed_conn *fconn;

	if (!fed)
		return EINVAL;

	fconn = lookup_fconn(fed, cid);
	if (fconn)
		mem_deref(fconn);

	return 0;
}

static enum fed_type fed_type(const char *type)
{
	if (str_casecmp(type, "udp") == 0)
		return FED_TYPE_UDP;
	else if (str_casecmp(type, "tcp") == 0)
		return FED_TYPE_TCP;
	else if (str_casecmp(type, "dtls") == 0)
		return FED_TYPE_DTLS;
	else if (str_casecmp(type, "tls") == 0)
		return FED_TYPE_TLS;
	else
		return FED_TYPE_NONE;
}

static void fed_destructor(void *arg)
{
	struct federate *fed = arg;

	if (fed->closeh)
		fed->closeh(fed, 0);

	list_flush(&fed->allocl);
}

int federate_alloc(struct federate **fedp, struct sa *local_addr,
		   const char *type)
{
	struct federate *fed = NULL;
	int err;

	fed = mem_zalloc(sizeof(*fed), fed_destructor);
	if (!fed)
		return ENOMEM;

	sa_cpy(&fed->lsa, local_addr);

	fed->type = fed_type(type);
	
	switch(fed->type) {
	case FED_TYPE_UDP:
		fed->inith = federate_udp_init;
		fed->closeh = federate_udp_close;
		fed->sendh = federate_udp_send;
		break;

	case FED_TYPE_DTLS:
		fed->inith = federate_dtls_init;
		fed->closeh = federate_dtls_close;
		fed->sendh = federate_dtls_send;
		break;

	default:
		break;
	}
	err = EINVAL;
	if (fed->inith) {
		err = fed->inith(fed, &fed->lsa);
		if (err)
			goto out;
	}

out:
	if (err)
		mem_deref(fed);
	else if (fedp)
		*fedp = fed;
	
	return err;
}

int federate_send(struct federate *fed, const struct sa *dst, struct mbuf *mb)
{
	int err = ENOSYS;
	
	if (!fed)
		return EINVAL;

	if (!fed->sendh)
		return ENOSYS;

	err = fed->sendh(fed, dst, mb);
	if (err)
		goto out;

 out:
	return err;
}

void federate_recv(struct federate *fed, struct mbuf *mb)
{
	struct fed_conn *fconn;
	size_t pos;
	uint16_t cid;
	uint16_t len;

	pos = mb->pos;
	cid = ntohs(mbuf_read_u16(mb));
	len = ntohs(mbuf_read_u16(mb));

	fconn = lookup_fconn(fed, cid);
	if (fconn)
		allocate_recv(fconn->al, mb, NULL, NULL, NULL);
	else {
		restund_debug("federate(%p): no allocation chan: %u\n",
			      fed, cid);
	}	
}


void federate_close(struct federate *fed, int err)
{
	restund_debug("federate_close(%p): err=%d\n", fed, err);

	if (fed->closeh) {
		fed->closeh(fed, err);
		fed->closeh = NULL;
	}

	mem_deref(fed);
}
