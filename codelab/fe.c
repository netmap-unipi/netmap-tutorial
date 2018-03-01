/*
 * This program reads UDP packets from the first netmap port and
 * selectively forwards them to the second or third port, depending
 * on the UDP destination port. The user can specify two UDP ports A and
 * B by command line: packets with destination port A will be forwarded
 * to the second netmap port; packets with destination port B will be
 * forwarded to the third netmap port; all the other packets are
 * dropped.
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

static int stop                   = 0;
static unsigned long long fwdback = 0;
static unsigned long long fwda    = 0;
static unsigned long long fwdb    = 0;
static unsigned long long tot     = 0;

static void
sigint_handler(int signum)
{
    stop = 1;
}

static int
rx_ready(struct nm_desc *nmd)
{
    unsigned int ri;

    for (ri = nmd->first_rx_ring; ri <= nmd->last_rx_ring; ri++) {
        struct netmap_ring *ring;

        ring = NETMAP_RXRING(nmd->nifp, ri);
        if (nm_ring_space(ring)) {
            return 1; /* there is something to read */
        }
    }

    return 0;
}

static inline int
pkt_get_udp_port(const char *buf)
{
    struct ether_header *ethh;
    struct ip *iph;
    struct udphdr *udph;

    ethh = (struct ether_header *)buf;
    if (ethh->ether_type != htons(ETHERTYPE_IP)) {
        /* Filter out non-IP traffic. */
        return 0;
    }
    iph = (struct ip *)(ethh + 1);
    if (iph->ip_p != IPPROTO_UDP) {
        /* Filter out non-UDP traffic. */
        return 0;
    }
    udph = (struct udphdr *)(iph + 1);

    /* Return destination port. */
    return ntohs(udph->uh_dport);
}

static void
forward_pkts(struct nm_desc *src, struct nm_desc *dst)
{
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
            char *txbuf            = NETMAP_BUF(txring, ts->buf_idx);

            ts->len = rs->len;
            memcpy(txbuf, rxbuf, ts->len);
            txhead = nm_ring_next(txring, txhead);
            ntx--;
            fwdback++;
            tot++;
        }
        /* Update state of netmap ring. */
        rxring->head = rxring->cur = rxhead;
        txring->head = txring->cur = txhead;
    }
}

static int
main_loop(const char *netmap_port_one, const char *netmap_port_two,
          const char *netmap_port_three, int udp_port_a, int udp_port_b)
{
    struct nm_desc *nmd_one;
    struct nm_desc *nmd_two;
    struct nm_desc *nmd_three;

    nmd_one = nm_open(netmap_port_one, NULL, 0, NULL);
    if (nmd_one == NULL) {
        if (!errno) {
            printf("Failed to nm_open(%s): not a netmap port\n",
                   netmap_port_one);
        } else {
            printf("Failed to nm_open(%s): %s\n", netmap_port_one,
                   strerror(errno));
        }
        return -1;
    }

    nmd_two = nm_open(netmap_port_two, NULL, 0, NULL);
    if (nmd_two == NULL) {
        if (!errno) {
            printf("Failed to nm_open(%s): not a netmap port\n",
                   netmap_port_two);
        } else {
            printf("Failed to nm_open(%s): %s\n", netmap_port_two,
                   strerror(errno));
        }
        return -1;
    }

    nmd_three = nm_open(netmap_port_three, NULL, 0, NULL);
    if (nmd_three == NULL) {
        if (!errno) {
            printf("Failed to nm_open(%s): not a netmap port\n",
                   netmap_port_three);
        } else {
            printf("Failed to nm_open(%s): %s\n", netmap_port_three,
                   strerror(errno));
        }
        return -1;
    }

    while (!stop) {
        /* Forward traffic from ports two and three back to port one. */
        forward_pkts(nmd_two, nmd_one);
        forward_pkts(nmd_three, nmd_one);
    }

    nm_close(nmd_one);
    nm_close(nmd_two);
    nm_close(nmd_three);

    printf("Total processed packets: %llu\n", tot);
    printf("Forwarded to port one  : %llu\n", fwdback);
    printf("Forwarded to port two  : %llu\n", fwda);
    printf("Forwarded to port three: %llu\n", fwdb);

    return 0;
}

static void
usage(char **argv)
{
    printf("usage: %s [-h] [-i NETMAP_PORT_ONE] "
           "[-i NETMAP_PORT_TWO] [-i NETMAP_PORT_THREE] "
           "[-p UDP_PORT_A] [-p UDP_PORT_B]\n",
           argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *netmap_port_one   = NULL;
    const char *netmap_port_two   = NULL;
    const char *netmap_port_three = NULL;
    int udp_port;
    int udp_port_a    = 8000;
    int udp_port_b    = 8001;
    int udp_port_args = 0;
    struct sigaction sa;
    int opt;
    int ret;

    while ((opt = getopt(argc, argv, "hi:p:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv);
            return 0;

        case 'i':
            if (netmap_port_one == NULL) {
                netmap_port_one = optarg;
            } else if (netmap_port_two == NULL) {
                netmap_port_two = optarg;
            } else if (netmap_port_three == NULL) {
                netmap_port_three = optarg;
            }
            break;

        case 'p':
            udp_port = atoi(optarg);
            if (udp_port <= 0 || udp_port >= 65535) {
                printf("    invalid UDP port %s\n", optarg);
                usage(argv);
            }
            switch (udp_port_args) {
            case 0:
                udp_port_a = udp_port;
                break;
            case 1:
                udp_port_b = udp_port;
                break;
            }
            udp_port_args++;
            break;

        default:
            printf("    unrecognized option '-%c'\n", opt);
            usage(argv);
            return -1;
        }
    }

    if (netmap_port_one == NULL) {
        printf("    missing netmap port #1\n");
        usage(argv);
    }

    if (netmap_port_two == NULL) {
        printf("    missing netmap port #2\n");
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
    (void)rx_ready;

    printf("Port one  : %s\n", netmap_port_one);
    printf("Port two  : %s\n", netmap_port_two);
    printf("Port three: %s\n", netmap_port_three);
    printf("UDP port A: %d\n", udp_port_a);
    printf("UDP port B: %d\n", udp_port_b);

    main_loop(netmap_port_one, netmap_port_two, netmap_port_three, udp_port_a,
              udp_port_b);

    (void) pkt_get_udp_port;

    return 0;
}
