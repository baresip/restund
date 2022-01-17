#include <re.h>

#include "restund.h"
#include "turn.h"

#include "federate.h"


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct federate *fed = arg;
	struct fed_conn *fconn;
	size_t pos;
	uint16_t cid;
	uint16_t len;
	
	restund_debug("federate_udp(%p): udp_recv_handler: %zu bytes from %J\n",
		      fed, mbuf_get_left(mb), src);

	federate_recv(fed, mb);
}

static void udp_err_handler(int err, void *arg)
{
	struct federate *fed = arg;
	
	restund_warning("federate: udp(%p) err=%m\n", fed->udp.sock, err);

	federate_close(fed, err);
}


int federate_udp_init(struct federate *fed, struct sa *lsa)
{
	int err;
	
	err = udp_listen(&fed->udp.sock, lsa,
			 udp_recv_handler, fed);
	if (err)
		goto out;

	udp_error_handler_set(fed->udp.sock, udp_err_handler);

 out:
	return err;
}

void federate_udp_close(struct federate *fed, int err)
{
	fed->err = err;
	fed->udp.sock = mem_deref(fed->udp.sock);
}

int federate_udp_send(struct federate *fed, const struct sa *dst,
		      struct mbuf *mb)
{
	int err;
	
	if (!fed || fed->type == FED_TYPE_UDP)
		return EINVAL;

	err = udp_send(fed->udp.sock, dst, mb);

	return err;
}

struct sa *federate_local_addr(struct federate *fed)
{
	if (!fed)
		return NULL;

	return &fed->lsa;
}
