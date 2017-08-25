/*
 * This program opens a netmap port and starts receiving packets,
 * counting all the UDP packets with a destination port specified
 * by command-line option.
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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

static int stop = 0;

static void
sigint_handler(int signum)
{
    stop = 1;
}

static inline int
udp_port_match(const char *buf, unsigned len, int udp_port)
{
    struct ether_header *ethh;
    struct iphdr *iph;
    struct udphdr *udph;

    ethh = (struct ether_header *)buf;
    if (ethh->ether_type != htons(ETHERTYPE_IP)) {
        /* Filter out non-IP traffic. */
        return 0;
    }
    iph = (struct iphdr *)(ethh + 1);
    if (iph->protocol != IPPROTO_UDP) {
        /* Filter out non-UDP traffic. */
        return 0;
    }
    udph = (struct udphdr *)(iph + 1);

    /* Match the destination port. */
    if (udph->dest == htons(udp_port)) {
        return 1;
    }

    return 0;
}

static int
main_loop(const char *netmap_port, int udp_port)
{
    struct nm_desc *nmd;

    nmd = nm_open(netmap_port, NULL, 0, NULL);
    /* check for errors */

    while (!stop) {
       int r;
       /* for each ring index from nmd->first_rx_ring to
        * nmd->last_rx_ring (included)
        */
       /* synchronize! */
       ioctl(nmd->fd, NIOCRXSYNC);
       for (r = nmd->first_rx_ring; r <= nmd->last_rx_ring; r++) {
           struct netmap_ring *ring = NETMAP_RXRING(nifp, r);
       
           /* for each packet from ring->head to ring->tail
            * (excluded) */
           for ( ; ring->head != ring->tail;
                ring->head = nm_ring_next(ring, ring->head)) {
                struct netmap_slot *slot = &ring->slot[ring->head];
                void *buf = NETMAP_BUF(ring, slot->buf_idx);
	       /* count if match */
	   }
	   /* update ring->head and ring->cur */
	   ring->cur = ring->head;
       }
    }


    return 0;
}

static void
usage(char **argv)
{
    printf("usage: %s [-h] [-p UDP_PORT] [-i NETMAP_PORT]\n", argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *netmap_port = NULL;
    int udp_port = 8000;
    struct sigaction sa;
    int opt;
    int ret;

    while ((opt = getopt(argc, argv, "hi:p:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv);
                return 0;

            case 'i':
                netmap_port = optarg;
                break;

            case 'p':
                udp_port = atoi(optarg);
                if (udp_port <= 0 || udp_port >= 65535) {
                    printf("    invalid UDP port %s\n", optarg);
                    usage(argv);
                }
                break;

            default:
                printf("    unrecognized option '-%c'\n", opt);
                usage(argv);
                return -1;
        }
    }

    if (netmap_port == NULL) {
        printf("    missing netmap port\n");
        usage(argv);
    }

    /* Register Ctrl-C handler. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }

    printf("Port    : %s\n", netmap_port);
    printf("UDP port: %d\n", udp_port);

    main_loop(netmap_port, udp_port);

    return 0;
}
