/*
 * Copyright (C) 2014 Michio Honda. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined (__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/module.h>
#include <sys/conf.h>

/* to compile netmap_kern.h */
#include <sys/malloc.h>
#include <machine/bus.h>
#include <sys/socket.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/sockio.h> /* XXX _IOWR. Should we use ioccom.h ? */
#include <sys/proc.h>
#include <net/if.h>
#include <net/if_var.h> /* struct ifnet */

#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL

#elif defined (linux)
#include <bsd_glue.h> /* from netmap-release */

#define ETHER_HDR_LEN	ETH_HLEN
#define ETHER_ADDR_LEN	6
struct ip {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#elif defined (__BIG_ENDIAN_BITFIELD)
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
} __packed __aligned(4);

#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif /* linux */

/* Common headers */
#define WITH_VALE
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */
#include <net/mymodule.h>

#define MY_NAME		"vale0:"

u_int my_lookup(struct nm_bdg_fwd *, uint8_t *, struct netmap_vp_adapter *);

uint16_t my_routes[NM_BDG_MAXPORTS];

u_int
my_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
		struct netmap_vp_adapter *vpna)
{
	char *buf = ft->ft_buf;
	u_int my_port = vpna->bdg_port;
#if 0

	/* You can do whatever youw ant on buf */
	/* You can also specify dst ring index on hint */

	return my_routes[my_port];
#endif
	int eth_type = ntohs(*(uint16_t *)(buf + 12));

	if (eth_type == 0x0800) {
		return my_port + 1;
	}
	return NM_BDG_BROADCAST;
}

static void
my_dtor(const struct netmap_vp_adapter *vpna)
{
	return;
}

/*
 * CLI backend
 */
static int
my_config(struct nm_ifreq *data)
{
	struct mmreq *mreq = (struct mmreq *)data;

	if (mreq->mr_sport >= NM_BDG_MAXPORTS) {
		D("invalid sport index %d", mreq->mr_sport);
		return EINVAL;
	}
	else if (mreq->mr_dport > NM_BDG_MAXPORTS) {
		D("invalid dport index %d", mreq->mr_dport);
		return EINVAL;
	}
	my_routes[mreq->mr_sport] = mreq->mr_dport;
	return 0;
}

static struct netmap_bdg_ops my_ops = {my_lookup, my_config, my_dtor};

#ifdef linux
static int mymodule_init(void);
static void mymodule_fini(void);

static int linux_mymodule_init(void)
{
	return -mymodule_init();
}

module_init(linux_mymodule_init);
module_exit(mymodule_fini);
MODULE_AUTHOR("Michio Honda");
MODULE_DESCRIPTION("A simple switching module");
MODULE_LICENSE("Dual BSD/GPL");
#endif /* Linux */

static int
mymodule_init(void)
{
	struct nmreq nmr;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, MY_NAME, strlen(MY_NAME));
	nmr.nr_cmd = NETMAP_BDG_REGOPS;
	if (netmap_bdg_ctl(&nmr, &my_ops)) {
		D("create a bridge named %s beforehand using vale-ctl",
			nmr.nr_name);
		return ENOENT;
	}
	bzero(my_routes, sizeof(my_routes));

	//printf("Mymodule: loaded module\n");
	return 0;
}

static void
mymodule_fini(void)
{
	struct nmreq nmr;
	int error;
	struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, MY_NAME, sizeof(nmr.nr_name));
	nmr.nr_cmd = NETMAP_BDG_REGOPS;
	error = netmap_bdg_ctl(&nmr, &tmp);
	if (error)
		D("failed to release VALE bridge %d", error);
	//printf("Mymodule: Unloaded module\n");
}

#ifdef __FreeBSD__
static int
mymodule_loader(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = mymodule_init();
		break;
	case MOD_UNLOAD:
		mymodule_fini();
		break;
	default:
		error = EINVAL;
	}
	return error;
}

DEV_MODULE(mymodule, mymodule_loader, NULL);
#endif /* __FreeBSD__ */
