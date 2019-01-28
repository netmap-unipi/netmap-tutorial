/*
 * This program forwards packets between two netmap ports, an external
 * port (ext) and an internal port (int). Packets flowing from ext to
 * int are filtered according to the rules provided through command
 * line. Packets flowing from int to ext bypass the filter, and they
 * are always forwarded.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <stdint.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <arpa/inet.h>

/* You can undef MULTIRING to get the simpler code, which assumes
 * that each netmap port has a single RX ring and a single TX ring. */
#define MULTIRING

static int			stop = 0;
static unsigned long long	fwd = 0;
static unsigned long long	tot = 0;

static void
sigint_handler(int signum)
{
	stop = 1;
}

struct filtrule {
	/* All fields are in network order. */
	uint32_t ip_daddr;
	uint32_t ip_mask;
	uint16_t dport;
	uint8_t ip_proto;
	uint8_t pad;
};

static inline int
pkt_select(const char *buf, struct filtrule *rules, int num_rules)
{
	struct ether_header *ethh;
	struct udphdr *udph;
	struct ip *iph;
	int i;

	ethh = (struct ether_header *)buf;
	if (ethh->ether_type != htons(ETHERTYPE_IP)) {
		/* Filter out non-IP traffic. */
		return 0;
	}
	iph = (struct ip *)(ethh + 1);
	udph = (struct udphdr *)(iph + 1);

	for (i = 0; i < num_rules; i++) {
		struct filtrule *rule = rules + i;

		if ((iph->ip_dst.s_addr & rule->ip_mask)
			== rule->ip_daddr &&
			(!rules->ip_proto || rule->ip_proto == iph->ip_p) &&
			(!rule->dport || rule->dport == udph->uh_dport)) {
			return 1; /* select */
		}
	}

	return 0; /* discard */
}

static void
forward_pkts(struct nm_desc *src, struct nm_desc *dst, struct filtrule *rules,
		int num_rules, int zerocopy)
{
#ifdef MULTIRING
	unsigned int si = src->first_rx_ring;
	unsigned int di = dst->first_tx_ring;

	while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
		struct netmap_ring *txring;
		struct netmap_ring *rxring;
		unsigned int rxhead, txhead;
		int nrx, ntx;

		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		nrx    = nm_ring_space(rxring);
		ntx    = nm_ring_space(txring);
		if (nrx == 0) {
			si++;
			continue;
		}
		if (ntx == 0) {
			di++;
			continue;
		}

		rxhead = rxring->head;
		txhead = txring->head;
		for (; nrx > 0 && ntx > 0;
				nrx--, rxhead = nm_ring_next(rxring, rxhead), tot++) {
			struct netmap_slot *rs = &rxring->slot[rxhead];
			struct netmap_slot *ts = &txring->slot[txhead];
			char *rxbuf            = NETMAP_BUF(rxring, rs->buf_idx);

			if (rules && !pkt_select(rxbuf, rules, num_rules)) {
				continue; /* discard */
			}

			ts->len = rs->len;
			if (zerocopy) {
				uint32_t idx = ts->buf_idx;
				ts->buf_idx  = rs->buf_idx;
				rs->buf_idx  = idx;
				/* report the buffer change. */
				ts->flags |= NS_BUF_CHANGED;
				rs->flags |= NS_BUF_CHANGED;
			} else {
				char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
				memcpy(txbuf, rxbuf, ts->len);
			}
			txhead = nm_ring_next(txring, txhead);
			ntx--;
			fwd++;
		}
		/* Update the pointers in the netmap rings. */
		rxring->head = rxring->cur = rxhead;
		txring->head = txring->cur = txhead;
	}
#else  /* !MULTIRING */
	struct netmap_ring *txring;
	struct netmap_ring *rxring;
	unsigned int rxhead, txhead;

	rxring = NETMAP_RXRING(src->nifp, 0);
	txring = NETMAP_TXRING(dst->nifp, 0);

	for (rxhead = rxring->head, txhead = txring->head;
			rxhead != rxring->tail && txhead != txring->tail;
				tot++, rxhead = nm_ring_next(rxring, rxhead)) {
		struct netmap_slot *rs = &rxring->slot[rxhead];
		struct netmap_slot *ts = &txring->slot[txhead];
		char *rxbuf            = NETMAP_BUF(rxring, rs->buf_idx);

		if (rules && !pkt_select(rxbuf, rules, num_rules)) {
			continue; /* discard */
		}

		ts->len = rs->len;
		if (zerocopy) {
			uint32_t idx = ts->buf_idx;
			ts->buf_idx  = rs->buf_idx;
			rs->buf_idx  = idx;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
		} else {
			char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
			memcpy(txbuf, rxbuf, ts->len);
		}
		txhead = nm_ring_next(txring, txhead);
		fwd++;
	}
	/* Update the pointers in the netmap rings. */
	rxring->head = rxring->cur = rxhead;
	txring->head = txring->cur = txhead;
#endif /* !MULTIRING */
}

static inline int
rx_ready(struct nm_desc *nmd)
{
#ifdef MULTIRING
	unsigned int ri;

	for (ri = nmd->first_rx_ring; ri <= nmd->last_rx_ring; ri++) {
		struct netmap_ring *ring;

		ring = NETMAP_RXRING(nmd->nifp, ri);
		if (nm_ring_space(ring)) {
			return 1; /* there is something to read */
		}
	}

	return 0;
#else  /* !MULTIRING */
	return nm_ring_space(NETMAP_RXRING(nmd->nifp, 0));
#endif /* !MULTIRING */
}

static int
main_loop(const char *ext_port_name, const char *int_port_name,
		struct filtrule *rules, int num_rules, int force_copy)
{
	struct nm_desc *ext_port;
	struct nm_desc *int_port;
	int zerocopy;

	ext_port = nm_open(ext_port_name, NULL, 0, NULL);
	if (ext_port == NULL) {
		if (!errno) {
			printf("Failed to nm_open(%s): not a netmap port\n",
					ext_port_name);
		} else {
			printf("Failed to nm_open(%s): %s\n", ext_port_name,
					strerror(errno));
		}
		return -1;
	}

	int_port = nm_open(int_port_name, NULL, NM_OPEN_NO_MMAP, ext_port);
	if (int_port == NULL) {
		if (!errno) {
			printf("Failed to nm_open(%s): not a netmap port\n",
					int_port_name);
		} else {
			printf("Failed to nm_open(%s): %s\n", int_port_name,
					strerror(errno));
		}
		return -1;
	}

	/* Check if we can do zerocopy. */
	zerocopy = !force_copy && (ext_port->mem == int_port->mem);
	printf("zerocopy %sabled\n", zerocopy ? "en" : "dis");

	while (!stop) {
		struct pollfd pfd[2];
		int ret;

		pfd[0].fd     = ext_port->fd;
		pfd[1].fd     = int_port->fd;
		pfd[0].events = 0;
		pfd[1].events = 0;
		if (!rx_ready(ext_port)) {
			/* Ran out of input packets on the first port, we need to
			 * wait for them. */
			pfd[0].events |= POLLIN;
		} else {
			/* We have input packets on the first port, let's wait for
			 * TX ring space in the other port. */
			pfd[1].events |= POLLOUT;
		}
		if (!rx_ready(int_port)) {
			/* Ran out of input packets on the second port, we need to
			 * wait for them. */
			pfd[1].events |= POLLIN;
		} else {
			/* We have input packets on the second port, let's wait for
			 * TX ring space in the other port. */
			pfd[0].events |= POLLOUT;
		}

		/* We poll with a timeout to have a chance to break the main loop if
		 * no packets are coming. */
		ret = poll(pfd, 2, 1000);
		if (ret < 0) {
			perror("poll()");
		} else if (ret == 0) {
			/* Timeout */
			continue;
		}

		/* Forward in the two directions. */
		forward_pkts(ext_port, int_port, rules, num_rules, zerocopy);
		forward_pkts(int_port, ext_port, NULL, 0, zerocopy);
	}

	nm_close(ext_port);
	nm_close(int_port);

	printf("Total processed packets: %llu\n", tot);
	printf("Forwarded packets      : %llu\n", fwd);
	printf("Dropped packets        : %llu\n", tot - fwd);

	return 0;
}

static void
usage(char **argv)
{
	printf("usage: %s [-h]\n"
		"    [-p x.y.z.w/mask:proto:dport (pass rule)] [-p ... ]\n"
		"    [-i INTERNAL_PORT]\n"
		"    [-e EXTERNAL_PORT]\n"
		"    [-c (disable zerocopy if supported)]\n"
		"\n"
		"  Zero or more pass rules can be specified. A zero value for"
		" mask, proto or dport means 'any'.\n",
		argv[0]);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
#define MAXRULES 16
	struct filtrule rules[MAXRULES];
	const char *ext_port_name = NULL;
	const char *int_port_name = NULL;
	struct sigaction sa;
	int force_copy = 0;
	int num_rules = 0;
	int opt, ret, i;

	while ((opt = getopt(argc, argv, "hi:e:p:c")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv);
			return 0;

		case 'i':
			int_port_name = optarg;
			break;

		case 'e':
			ext_port_name = optarg;
			break;

		case 'p': {
			char *copy = strdup(optarg);
			char *ipstr, *maskstr, *protostr, *portstr, *null;
			int port, proto, mask;
			struct in_addr ip;
			int ret;

			assert(copy != NULL);
			ipstr = strtok(copy, "/");
			if (!ipstr) {
				printf("    invalid -p '%s': no IPv4 found\n",
					optarg);
				usage(argv);
			}
			ret = inet_pton(AF_INET, ipstr, &ip);
			if (ret <= 0) {
				printf("    invalid IPv4 '%s'\n",
					ipstr);
				usage(argv);
			}

			maskstr = strtok(NULL, ":");
			if (!maskstr) {
				printf("    invalid -p '%s': no mask found\n",
					optarg);
				usage(argv);
			}
			mask = atoi(maskstr);
			if (mask < 0 || mask > 31) {
				printf("    invalid mask '%s'\n",
					maskstr);
				usage(argv);
			}

			protostr = strtok(NULL, ":");
			if (!protostr) {
				printf("    invalid -p '%s': no proto found\n",
					optarg);
				usage(argv);
			}
			proto = atoi(protostr);
			if (proto < 0 || proto > 255) {
				printf("    invalid proto '%s'\n",
					protostr);
				usage(argv);
			}

			portstr = strtok(NULL, ":");
			if (!portstr) {
				printf("    invalid -p '%s': no port found\n",
					optarg);
				usage(argv);
			}
			port = atoi(portstr);
			if (port < 0 || port > (1<<16)-1) {
				printf("    invalid port '%s'\n",
					portstr);
				usage(argv);
			}

			null = strtok(NULL, ":");
			if (null) {
				printf("    invalid -p '%s': trailing chars\n",
					optarg);
				usage(argv);
			}
			free(copy);

			if (num_rules >= MAXRULES) {
				printf("    too many rules, bailing out\n");
				exit(EXIT_FAILURE);
			}

			rules[num_rules].ip_mask =
				(((uint64_t)1ULL << mask) - 1ULL) << (32 - mask);
			rules[num_rules].ip_mask = htonl(rules[num_rules].ip_mask);
			rules[num_rules].ip_daddr = ip.s_addr & rules[num_rules].ip_mask;
			rules[num_rules].ip_proto = proto;
			rules[num_rules].dport = htons(port);
			num_rules++;
			break;
		}

		case 'c':
			force_copy = 1;
			break;

		default:
			printf("    unrecognized option '-%c'\n", opt);
			usage(argv);
			return -1;
		}
	}

	if (ext_port_name == NULL) {
		printf("    missing external port\n");
		usage(argv);
	}

	if (int_port_name == NULL) {
		printf("    missing internal port\n");
		usage(argv);
	}

	/* Register Ctrl-C handler. */
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	ret         = sigaction(SIGINT, &sa, NULL);
	if (ret) {
		perror("sigaction(SIGINT)");
		exit(EXIT_FAILURE);
	}

	printf("External port: %s\n", ext_port_name);
	printf("Internal port: %s\n", int_port_name);
	printf("Rules:\n");
	for (i = 0; i < num_rules; i++) {
		printf("    pass ip_daddr 0x%08x/0x%08x ip_proto %u "
			"dport %u\n",
			ntohl(rules[i].ip_daddr), ntohl(rules[i].ip_mask),
			rules[i].ip_proto, ntohs(rules[i].dport));
	}

	main_loop(ext_port_name, int_port_name, rules, num_rules, force_copy);

	return 0;
}
