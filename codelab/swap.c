/*
 * This program forwards UDP packets between two netmap ports.
 * Only UDP packets with a destination port specified
 * by command-line option are forwarded, while all the other ones are
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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

static int stop = 0;
static unsigned long long swapped = 0;
static unsigned long long tot = 0;

static void
sigint_handler(int signum)
{
    stop = 1;
}

static int
rx_ready(struct nm_desc *nmd)
{
    unsigned int ri;

    for (ri = nmd->first_rx_ring; ri <= nmd->last_rx_ring; ri ++) {
            struct netmap_ring *ring;

            ring = NETMAP_RXRING(nmd->nifp, ri);
            if (nm_ring_space(ring)) {
                return 1; /* there is something to read */
            }
    }

    return 0;
}

/* Swap UDP source and destination ports. Returns 1 if a
 * swap was performed, 0 otherwise. */
static inline int
pkt_udp_port_swap(char *buf)
{
    struct ether_header *ethh;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t tmp;

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
    tmp = udph->source;
    udph->source = udph->dest;
    udph->dest = tmp;

    return 1;
}


static int
main_loop(const char *netmap_port_one, const char *netmap_port_two)
{
    struct nm_desc *nmd_one;
    struct nm_desc *nmd_two;
    int zerocopy;

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

    nmd_two = nm_open(netmap_port_two, NULL, NM_OPEN_NO_MMAP, nmd_one);
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

    /* Check if we can do zerocopy. */
    zerocopy = (nmd_one->mem == nmd_two->mem);
    printf("zerocopy %sabled\n", zerocopy ? "en" : "dis");

    while (!stop) {
    }

    nm_close(nmd_one);
    nm_close(nmd_two);

    printf("Total processed packets: %llu\n", tot);
    printf("Swapped packets        : %llu\n", swapped);

    return 0;
}

static void
usage(char **argv)
{
    printf("usage: %s [-h] [-i NETMAP_PORT_ONE] "
           "[-i NETMAP_PORT_TWO]\n", argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *netmap_port_one = NULL;
    const char *netmap_port_two = NULL;
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
                }
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
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    (void)rx_ready;

    printf("Port one: %s\n", netmap_port_one);
    printf("Port two: %s\n", netmap_port_two);

    main_loop(netmap_port_one, netmap_port_two);

    return 0;
}
