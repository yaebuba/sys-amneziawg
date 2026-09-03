/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * The tunnel as an lwIP network interface. See awg_netif.h for why.
 */
#include <string.h>
#include <sys/socket.h>

#include "awg_netif.h"
#include "awg_noise.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "lwip/sys.h"

/* Matches the MTU in lwipopts.h; see the note there for where it comes from. */
#define TUNNEL_MTU 1400

static struct netif      g_netif;
static const awg_config *g_cfg;
static awg_session      *g_sess;
static int               g_fd = -1;
static struct sockaddr_storage g_peer;
static socklen_t         g_peer_len;
static bool              g_ready = false;

/* Sealed packets are built here rather than on the stack: lwIP calls output
 * from deep inside its own call chain and the main thread has 32 KiB. */
static uint8_t g_out[2048];

/*
 * lwIP hands us a finished IP packet. Seal it into the session and put it on
 * the wire.
 *
 * The pbuf may be a chain, so it is flattened first - pbuf_copy_partial walks
 * the chain for us.
 */
static err_t tunnel_output(struct netif *nif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    (void)nif; (void)ipaddr;   /* point-to-point: there is only one next hop */

    if (!g_sess || !g_sess->established) return ERR_IF;
    if (p->tot_len > TUNNEL_MTU) return ERR_MEM;

    uint8_t inner[TUNNEL_MTU];
    u16_t len = pbuf_copy_partial(p, inner, (u16_t)p->tot_len, 0);
    if (len != p->tot_len) return ERR_BUF;

    int n = awg_session_build_data(g_sess, g_cfg, inner, len,
                                   g_out, (int)sizeof(g_out),
                                   (uint64_t)sys_now());
    if (n < 0) return ERR_MEM;

    if (sendto(g_fd, g_out, (size_t)n, 0,
               (struct sockaddr *)&g_peer, g_peer_len) < 0)
        return ERR_IF;

    return ERR_OK;
}

static err_t tunnel_netif_init(struct netif *nif)
{
    nif->name[0] = 'a';
    nif->name[1] = 'w';
    nif->output  = tunnel_output;      /* IPv4 straight out, no ARP step */
    nif->mtu     = TUNNEL_MTU;

    /* No broadcast, no ARP: the peer is the only destination that exists on
     * this link, and it is reached by encryption rather than by address. */
    nif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

int awg_netif_start(const awg_config *cfg, awg_session *sess,
                    int fd, const void *peer_sockaddr, int peer_len)
{
    if (peer_len <= 0 || (size_t)peer_len > sizeof(g_peer)) return -1;

    g_cfg  = cfg;
    g_sess = sess;
    g_fd   = fd;
    memcpy(&g_peer, peer_sockaddr, (size_t)peer_len);
    g_peer_len = (socklen_t)peer_len;

    lwip_init();

    ip4_addr_t addr, mask, gw;
    addr.addr = cfg->address;        /* already network order */
    /*
     * A /32 with no gateway. Everything the peer accepts is reachable, and
     * routing decisions do not belong here - the peer's AllowedIPs already
     * said it takes 0.0.0.0/0. Making this the default interface sends all
     * traffic down it.
     */
    IP4_ADDR(&mask, 255, 255, 255, 255);
    IP4_ADDR(&gw, 0, 0, 0, 0);

    if (!netif_add(&g_netif, &addr, &mask, &gw, NULL,
                   tunnel_netif_init, ip4_input))
        return -1;

    netif_set_default(&g_netif);
    netif_set_up(&g_netif);
    netif_set_link_up(&g_netif);

    g_ready = true;
    return 0;
}

void awg_netif_set_fd(int fd)
{
    g_fd = fd;
}

void awg_netif_input(const uint8_t *packet, int len)
{
    if (!g_ready || len <= 0) return;

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return;                       /* pool exhausted: drop, as a NIC would */

    if (pbuf_take(p, packet, (u16_t)len) != ERR_OK) {
        pbuf_free(p);
        return;
    }

    /* netif->input is ip_input, set when the interface was added. It takes
     * ownership of the pbuf on success and frees it on failure. */
    if (g_netif.input(p, &g_netif) != ERR_OK)
        pbuf_free(p);
}

void awg_netif_poll(void)
{
    if (g_ready) sys_check_timeouts();
}

bool awg_netif_ready(void)
{
    return g_ready;
}
