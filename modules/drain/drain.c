#include <re.h>
#include <restund.h>


static bool is_draining = false;


/*
 * If is_draining == true, prevents new allocations and denies allocation
 * refresh by replying with a '508 Insufficient Capacity' message.
 */
static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	int err;
	struct stun_attr *lt;
	(void)dst;

	if (is_draining) {
		switch (stun_msg_method(msg)) {

		case STUN_METHOD_ALLOCATE:
			restund_info("received ALLOCATE request while in "
				     "drain mode\n");
			goto unavailable;

		case STUN_METHOD_REFRESH:
			lt = stun_msg_attr(msg, STUN_ATTR_LIFETIME);

			if (lt && lt->v.lifetime > 0) {
				restund_info("received REFRESH request while "
					     "in drain mode\n");
				goto unavailable;
			}

			break;

		default:
			break;
		}
	}

	return false;

unavailable:
	err = stun_ereply(proto, sock, src, 0, msg, 508, "Draining", NULL, 0,
			  ctx->fp, 1, STUN_ATTR_SOFTWARE, restund_software);

	if (err) {
		restund_warning("drain reply error: %m\n", err);
	}

	return true;
}


static void drain_print(struct mbuf *mb)
{
	(void)mbuf_printf(mb, "is_draining: %d\n", is_draining);
}


static void drain_enable(struct mbuf *mb)
{
	is_draining = true;
	drain_print(mb);
}


static void drain_disable(struct mbuf *mb)
{
	is_draining = false;
	drain_print(mb);
}


static struct restund_cmdsub cmd_drain_print = {
	.cmdh = drain_print,
	.cmd  = "drain_state",
};


static struct restund_cmdsub cmd_drain_enable = {
	.cmdh = drain_enable,
	.cmd  = "drain_enable",
};


static struct restund_cmdsub cmd_drain_disable = {
	.cmdh = drain_disable,
	.cmd  = "drain_disable",
};


struct restund_stun stun = {.reqh = request_handler};

static int module_init(void)
{
	restund_stun_register_handler(&stun);
	restund_cmd_subscribe(&cmd_drain_print);
	restund_cmd_subscribe(&cmd_drain_enable);
	restund_cmd_subscribe(&cmd_drain_disable);

	restund_debug("drain: module loaded\n");

	return 0;
}


static int module_close(void)
{
	restund_cmd_unsubscribe(&cmd_drain_enable);
	restund_cmd_unsubscribe(&cmd_drain_disable);
	restund_cmd_unsubscribe(&cmd_drain_print);
	restund_stun_unregister_handler(&stun);

	restund_debug("drain: module closed\n");

	return 0;
}


const struct mod_export DECL_EXPORTS(drain) = {
	.name  = "drain",
	.type  = "stun",
	.init  = module_init,
	.close = module_close,
};
