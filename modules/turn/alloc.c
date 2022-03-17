/**
 * @file alloc.c Turn Server Allocation
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <restund.h>
#include "turn.h"


enum {
	PERM_HASH_SIZE = 16,
	CHAN_HASH_SIZE = 16,
	PORT_TRY_MAX = 32,
	TCP_MAX_TXQSZ  = 8192,
};


static uint8_t sa_stunaf(const struct sa *sa)
{
	switch (sa_af(sa)) {

	case AF_INET:
		return STUN_AF_IPv4;

	case AF_INET6:
		return STUN_AF_IPv6;
	}

	return 0;
}


static const struct sa *relay_addr(const struct turnd *turnd, uint8_t af)
{
	switch (af) {

	case STUN_AF_IPv4:
		return &turnd->rel_addr;

	case STUN_AF_IPv6:
		return &turnd->rel_addr6;
	}

	return NULL;
}


static void destructor(void *arg)
{
	struct allocation *al = arg;

	hash_flush(al->perms);
	mem_deref(al->perms);
	mem_deref(al->chans);
	restund_debug("turn: allocation %p destroyed\n", al);
	hash_unlink(&al->he);
	tmr_cancel(&al->tmr);
	mem_deref(al->username);
	mem_deref(al->cli_sock);
	mem_deref(al->rel_us);
	mem_deref(al->rsv_us);
	turndp()->allocc_cur--;

	if (al->cid)
		federate_del_conn(turndp()->federate, al->cid);
}


static void timeout(void *arg)
{
	struct allocation *al = arg;

	restund_debug("turn: allocation %p expired\n", al);
	mem_deref(al);
}


int allocate_recv(struct allocation *al, struct mbuf *mb,
		  struct chan *chan, struct perm *perm,
		  const struct sa *src)
{
	int err;

	if (chan || al->relaxed) {
		uint16_t len = mbuf_get_left(mb);
		size_t start;

		mb->pos -= 4;
		start = mb->pos;

		if (chan)
			(void)mbuf_write_u16(mb, htons(chan_numb(chan)));
		else
			(void)mbuf_write_u16(mb, 0xffff);
			
		(void)mbuf_write_u16(mb, htons(len));

		if (al->proto == IPPROTO_TCP) {

			mb->pos = mb->end;

			/* padding */
			while (len++ & 0x03) {
				err = mbuf_write_u8(mb, 0x00);
				if (err)
					goto out;
			}
		}

		mb->pos = start;
		err = stun_send(al->proto, al->cli_sock, &al->cli_addr, mb);
		mb->pos += 4;
	}
	else {
		if (!src) {
			err = EINVAL;
			goto out;
		}
		err = stun_indication(al->proto, al->cli_sock,
				      &al->cli_addr, 0, STUN_METHOD_DATA,
				      NULL, 0, false, 2,
				      STUN_ATTR_XOR_PEER_ADDR, src,
				      STUN_ATTR_DATA, mb);
	}

 out:
	if (err)
		turndp()->errc_rx++;
	else {
		const size_t bytes = mbuf_get_left(mb);

		if (perm)
			perm_rx_stat(perm, bytes);

		turndp()->bytec_rx += bytes;
	}

	return err;
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct allocation *al = arg;
	struct chan *chan = NULL;
	struct perm *perm = NULL;
	
	if (al->proto == IPPROTO_TCP) {

		if (tcp_conn_txqsz(al->cli_sock) > TCP_MAX_TXQSZ) {
			++al->dropc_rx;
			return;
		}
	}

	if (!al->relaxed) {
		perm = perm_find(al->perms, src);
		if (!perm) {
			++al->dropc_rx;
			return;
		}
		chan = chan_peer_find(al->chans, src);
	}

	allocate_recv(al, mb, chan, perm, src);
}

static int relay_listen(const struct sa *rel_addr, struct allocation *al,
			const struct stun_even_port *even)
{
	uint32_t i;
	int err = 0;

	for (i=0; i<PORT_TRY_MAX; i++) {

		err = udp_listen(&al->rel_us, rel_addr, udp_recv, al);
		if (err)
			break;

		err = udp_local_get(al->rel_us, &al->rel_addr);
		if (err) {
			al->rel_us = mem_deref(al->rel_us);
			break;
		}

		if (!even)
			break;

		restund_debug("turn: try#%u: %J\n", i, &al->rel_addr);

		if (sa_port(&al->rel_addr) & 0x1) {
			al->rel_us = mem_deref(al->rel_us);
			continue;
		}

		if (!even->r)
			break;

		al->rsv_addr = al->rel_addr;
		sa_set_port(&al->rsv_addr, sa_port(&al->rel_addr) + 1);

		err = udp_listen(&al->rsv_us, &al->rsv_addr, NULL, NULL);
		if (err) {
			al->rel_us = mem_deref(al->rel_us);
			continue;
		}
		break;
	}

	return (i == PORT_TRY_MAX) ? EADDRINUSE : err;
}


static bool rsvt_handler(struct le *le, void *arg)
{
	struct allocation *al = le->data;
	uint64_t rsvt = *(uint64_t *)arg;

	if (sa_stunaf(&al->rsv_addr) != ((rsvt >> 24) & 0xff))
		return false;

	if (sa_port(&al->rsv_addr) != (rsvt & 0xffff))
		return false;

	return true;
}


static int rsvt_listen(const struct hash *ht, struct allocation *al,
		      uint64_t rsvt)
{
	struct allocation *alr;

	alr = list_ledata(hash_lookup(ht, (uint32_t)(rsvt >> 32),
				      rsvt_handler, &rsvt));
	if (!alr)
		return ENOENT;

	al->rel_us = alr->rsv_us;
	udp_handler_set(al->rel_us, udp_recv, al);
	alr->rsv_us = NULL;
	al->rel_addr = alr->rsv_addr;
	sa_init(&alr->rsv_addr, AF_UNSPEC);

	return 0;
}


void allocate_request(struct turnd *turnd, struct allocation *alx,
		      struct restund_msgctx *ctx, int proto, void *sock,
		      const struct sa *src, const struct sa *dst,
		      const struct stun_msg *msg)
{
	struct stun_attr *reqaf, *attr, *even, *rsvt;
	struct allocation *al = NULL;
	const struct sa *rel_addr;
	struct sa public_addr;
	struct federate *fed = NULL;
	uint32_t lifetime;
	int err = 0, rerr;
	uint64_t rsv;
	uint8_t af;
	bool public = false;
	char *uname;
	
	restund_debug("turn: allocate_request: alx=%p src=%J dst=%J\n",
		      alx, src, dst);

	/* Existing allocation */
	if (alx) {
		if (!memcmp(alx->tid, stun_msg_tid(msg), sizeof(alx->tid)) &&
		    proto == IPPROTO_UDP) {
			lifetime = (uint32_t)(tmr_get_expire(&alx->tmr)/1000);
			goto reply;
		}

		restund_debug("turn: allocation already exists (%J)\n", src);
		++turnd->reply.scode_437;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   437, "Allocation TID Mismatch",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Requested Address Family */
	reqaf = stun_msg_attr(msg, STUN_ATTR_REQ_ADDR_FAMILY);
	af = reqaf ? reqaf->v.req_addr_family : STUN_AF_IPv4;

	rel_addr = relay_addr(turnd, af);
	if (!sa_isset(rel_addr, SA_ADDR)) {
		restund_info("turn: unsupported address family: %u\n", af);
		++turnd->reply.scode_440;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   440, "Address Family not Supported",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Requested Transport */
	attr = stun_msg_attr(msg, STUN_ATTR_REQ_TRANSPORT);
	if (!attr) {
		restund_info("turn: requested transport missing\n");
		++turnd->reply.scode_400;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   400, "Requested Transport Missing",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}
	else if (attr->v.req_transport != IPPROTO_UDP) {
		restund_info("turn: unsupported transport protocol: %u\n",
			     attr->v.req_transport);
		++turnd->reply.scode_442;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   442, "Unsupported Transport Protocol",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Don't Fragment */
	attr = stun_msg_attr(msg, STUN_ATTR_DONT_FRAGMENT);
	if (attr) {
		struct stun_unknown_attr ua;

		ua.typev[0] = STUN_ATTR_DONT_FRAGMENT;
		ua.typec = 1;

		restund_info("turn: requested don't fragment\n");
		++turnd->reply.scode_420;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   420, "Unknown Attribute",
				   ctx->key, ctx->keylen, ctx->fp, 2,
				   STUN_ATTR_UNKNOWN_ATTR, &ua,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Even Port / Reservation Token */
	even = stun_msg_attr(msg, STUN_ATTR_EVEN_PORT);
	rsvt = stun_msg_attr(msg, STUN_ATTR_RSV_TOKEN);
	if ((even && rsvt) || (reqaf && rsvt)) {
		restund_info("turn: even-port/req-af + rsv-token requested\n");
		++turnd->reply.scode_400;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   400, "Bad Request",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Lifetime */
	attr = stun_msg_attr(msg, STUN_ATTR_LIFETIME);
	lifetime = attr ? attr->v.lifetime : TURN_DEFAULT_LIFETIME;
	lifetime = MAX(lifetime, TURN_DEFAULT_LIFETIME);
	lifetime = MIN(lifetime, turnd->lifetime_max);

	/* Create allocation state */
	al = mem_zalloc(sizeof(*al), destructor);
	if (!al) {
		restund_warning("turn: no memory for allocation\n");
		++turnd->reply.scode_500;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   500, "Server Error",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	hash_append(turnd->ht_alloc, sa_hash(src, SA_ALL), &al->he, al);
	tmr_start(&al->tmr, lifetime * 1000, timeout, al);
	attr = stun_msg_attr(msg, STUN_ATTR_USERNAME);
	if (attr) {
		uname = attr->v.username;
		if (strstr(uname, SFT_TOKEN) == uname) {
			al->relaxed = true;

			fed = turndp()->federate;
			if (fed) {
				al->cid = federate_add_conn(fed, al);
				restund_debug("alloc(%p): cid=%u\n",
					      al, al->cid);
				//uname += str_len(SFT_TOKEN);
			}
		}
	}
	if (uname)
		str_dup(&al->username, uname);
	else
		al->username = NULL;
	memcpy(al->tid, stun_msg_tid(msg), sizeof(al->tid));
	al->cli_sock = mem_ref(sock);
	al->cli_addr = *src;
	al->srv_addr = *dst;
	al->proto = proto;
	sa_init(&al->rsv_addr, AF_UNSPEC);
	turndp()->allocc_tot++;
	turndp()->allocc_cur++;

	/* Permissions */
	err = perm_hash_alloc(&al->perms, PERM_HASH_SIZE);
	if (err) {
		restund_warning("turn: perm list alloc: %m\n", err);
		++turnd->reply.scode_500;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   500, "Server Error",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Channels */
	err = chanlist_alloc(&al->chans, CHAN_HASH_SIZE);
	if (err) {
		restund_warning("turn: chan list alloc: %m\n", err);
		++turnd->reply.scode_500;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   500, "Server Error",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	/* Relay socket */
	if (rsvt)
		err = rsvt_listen(turnd->ht_alloc, al, rsvt->v.rsv_token);
	else
		err = relay_listen(rel_addr, al, even ? &even->v.even_port :
				   NULL);

	if (err) {
		restund_warning("turn: relay listen: %m\n", err);
		++turnd->reply.scode_508;
		rerr = stun_ereply(proto, sock, src, 0, msg,
				   508, "Insufficient Port Capacity",
				   ctx->key, ctx->keylen, ctx->fp, 1,
				   STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	udp_rxbuf_presz_set(al->rel_us, 4);
	if (turndp()->udp_sockbuf_size > 0)
		(void)udp_sockbuf_set(al->rel_us, turndp()->udp_sockbuf_size);

	restund_debug("turn: allocation %p created %s/%J/%J - %J (%us)\n",
		      al, stun_transp_name(al->proto), &al->cli_addr,
		      &al->srv_addr, &al->rel_addr, lifetime);

	alx = al;

 reply:
	if (alx->rsv_us) {
		rsv  = (uint64_t)sa_hash(src, SA_ALL) << 32;
		rsv |= (uint64_t)sa_stunaf(&alx->rsv_addr) << 24;
		rsv += sa_port(&alx->rsv_addr);
	}

	/* handle NAT'ed turn-server with public IP-address */
	af = sa_stunaf(&alx->rel_addr);
	if (af == STUN_AF_IPv4 && sa_isset(&turnd->public_addr, SA_ADDR)) {
		public_addr = turnd->public_addr;
		sa_set_port(&public_addr, sa_port(&alx->rel_addr));
		public = true;

		restund_debug("turn: mapping to public:  %J  -->  %J\n",
			     &alx->rel_addr, &public_addr);
	}

	if (fed && alx->cid) {
		rerr = stun_reply(proto, sock, src, 0, msg,
				  ctx->key, ctx->keylen, ctx->fp, 6,
				  STUN_ATTR_XOR_RELAY_ADDR,
				  federate_local_addr(fed),
				  STUN_ATTR_LIFETIME, &lifetime,
				  STUN_ATTR_RSV_TOKEN,
				  alx->rsv_us ? &rsv : NULL,
				  STUN_ATTR_XOR_MAPPED_ADDR, src,
				  STUN_ATTR_CHANNEL_NUMBER, &alx->cid,
				  STUN_ATTR_SOFTWARE, restund_software);
	}
	else {
		rerr = stun_reply(proto, sock, src, 0, msg,
				  ctx->key, ctx->keylen, ctx->fp, 5,
				  STUN_ATTR_XOR_RELAY_ADDR,
				  public ? &public_addr : &alx->rel_addr,
				  STUN_ATTR_LIFETIME, &lifetime,
				  STUN_ATTR_RSV_TOKEN, alx->rsv_us?&rsv : NULL,
				  STUN_ATTR_XOR_MAPPED_ADDR, src,
				  STUN_ATTR_SOFTWARE, restund_software);
	}
	err = rerr;
 out:
	if (rerr)
		restund_warning("turn: allocate reply: %m\n", rerr);

	if (err)
		mem_deref(al);
}


void refresh_request(struct turnd *turnd, struct allocation *al,
		     struct restund_msgctx *ctx,
		     int proto, void *sock, const struct sa *src,
		     const struct stun_msg *msg)
{
	struct stun_attr *attr;
	uint32_t lifetime;
	int err;

	attr = stun_msg_attr(msg, STUN_ATTR_REQ_ADDR_FAMILY);
	if (attr && attr->v.req_addr_family != sa_stunaf(&al->rel_addr)) {
		restund_info("turn: refresh address family mismatch\n");
		++turnd->reply.scode_443;
		err = stun_ereply(proto, sock, src, 0, msg,
				  443, "Peer Address Family Mismatch",
				  ctx->key, ctx->keylen, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto out;
	}

	attr = stun_msg_attr(msg, STUN_ATTR_LIFETIME);
	lifetime = attr ? attr->v.lifetime : TURN_DEFAULT_LIFETIME;
	lifetime = lifetime ? MAX(lifetime, TURN_DEFAULT_LIFETIME) : 0;
	lifetime = MIN(lifetime, turnd->lifetime_max);

	tmr_start(&al->tmr, lifetime * 1000, timeout, al);

	restund_debug("turn: allocation %p refresh (%us)\n", al, lifetime);

	err = stun_reply(proto, sock, src, 0, msg,
			 ctx->key, ctx->keylen, ctx->fp, 2,
			 STUN_ATTR_LIFETIME, &lifetime,
			 STUN_ATTR_SOFTWARE, restund_software);

 out:
	if (err) {
		restund_warning("turn: refresh reply: %m\n", err);
	}
}
