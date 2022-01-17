enum fed_type {
	FED_TYPE_NONE = 0,
	FED_TYPE_UDP = 1,
	FED_TYPE_TCP = 2,
	FED_TYPE_DTLS = 3,
	FED_TYPE_TLS = 4
};


typedef int (federate_init_h)(struct federate *fed, struct sa *lsa);
typedef void (federate_close_h)(struct federate *fed, int err);
typedef int (federate_send_h)(struct federate *fed, const struct sa *dst,
			      struct mbuf *mb);


struct federate {
	enum fed_type type;
	struct {
		struct udp_sock *sock;
	} udp;
	struct {
		struct tls *tls;
		struct dtls_sock *sock;
		struct list connl;
	} dtls;
	
	struct sa lsa; /* local address */
	struct list allocl;
	int err;

	federate_init_h *inith;
	federate_close_h *closeh;
	federate_send_h *sendh;
};

struct fed_conn {
	struct allocation *al;
	uint16_t cid;

	struct le le; /* Member of federate alloc list */
};

void federate_recv(struct federate *fed, struct mbuf *mb);
void federate_close(struct federate *fed, int err);

/* UDP */
int  federate_udp_init(struct federate *fed, struct sa *lsa);
void federate_udp_close(struct federate *fed, int err);
int  federate_udp_send(struct federate *fed, const struct sa *dst,
		       struct mbuf *mb);

/* DTLS */
int  federate_dtls_init(struct federate *fed, struct sa *lsa);
void federate_dtls_close(struct federate *fed, int err);
int  federate_dtls_send(struct federate *fed, const struct sa *dst,
			struct mbuf *mb);



