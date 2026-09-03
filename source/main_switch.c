/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * sys-amneziawg : the system module entry point.
 *
 * Stages 1-3 spoke the AmneziaWG protocol and hand-built single IP packets to
 * prove the tunnel carried them. That was scaffolding. This build hands the
 * tunnel to lwIP and asks it to fetch a web page - which needs a three-way
 * handshake, sequence numbers, windows, retransmission and a graceful close,
 * all travelling encrypted.
 *
 * If that works, the remaining piece is stage 5: intercepting the console's
 * own socket calls and pointing them at this stack instead of the internet.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <switch.h>

#include "awg.h"
#include "awg_noise.h"
#include "awg_session.h"
#include "awg_netif.h"
#include "awg_proxy.h"

#include "lwip/tcp.h"
#include "lwip/ip_addr.h"
#include "lwip/stats.h"

#define INNER_HEAP_SIZE 0x200000

#define CFG_DIR   "sdmc:/config/sys-amneziawg"
#define CONF_PATH CFG_DIR "/awg.conf"
#define LOG_PATH  CFG_DIR "/sys-amneziawg.log"

#define FETCH_EVERY_MS 300000   /* a liveness check, not the main event */

u32 __nx_applet_type      = AppletType_None;
u32 __nx_fs_num_sessions  = 1;
u32 __nx_fsdev_direntry_cache_size = 1;

static char g_heap[INNER_HEAP_SIZE];
static volatile bool g_stop = false;

static uint8_t g_wire[4096];
static uint8_t g_rx[4096];
static uint8_t g_inner[2048];

void __libnx_initheap(void)
{
    extern char *fake_heap_start;
    extern char *fake_heap_end;
    fake_heap_start = g_heap;
    fake_heap_end   = g_heap + sizeof(g_heap);
}

/* The configuration stage 2 proved. Trimming it is the last job, not this one. */
static const SocketInitConfig g_sockCfg = {
    .tcp_tx_buf_size     = 0x1000,
    .tcp_rx_buf_size     = 0x1000,
    .tcp_tx_buf_max_size = 0x4000,
    .tcp_rx_buf_max_size = 0x4000,
    .udp_tx_buf_size     = 0x2400,
    .udp_rx_buf_size     = 0x8000,
    .sb_efficiency       = 4,
    .num_bsd_sessions    = 4,
    .bsd_service_type    = BsdServiceType_System,
};

void __appInit(void)
{
    Result rc;
    rc = smInitialize();                 if (R_FAILED(rc)) diagAbortWithResult(rc);
    rc = fsInitialize();                 if (R_FAILED(rc)) diagAbortWithResult(rc);
    fsdevMountSdmc();
    rc = nifmInitialize(NifmServiceType_User); if (R_FAILED(rc)) diagAbortWithResult(rc);
    rc = timeInitialize();               if (R_FAILED(rc)) diagAbortWithResult(rc);
    rc = socketInitialize(&g_sockCfg);   if (R_FAILED(rc)) diagAbortWithResult(rc);
    smExit();
}

void __appExit(void)
{
    socketExit();
    timeExit();
    nifmExit();
    fsdevUnmountAll();
    fsExit();
}

static void wait_for_network(void)
{
    NifmInternetConnectionStatus st;
    NifmInternetConnectionType type;
    u32 strength;

    for (int i = 0; i < 150 && !g_stop; i++) {
        if (R_SUCCEEDED(nifmGetInternetConnectionStatus(&type, &strength, &st))
            && st == NifmInternetConnectionStatus_Connected)
            return;
        svcSleepThread(2000000000ULL);
    }
}

static uint64_t now_ms(void)
{
    return armTicksToNs(armGetSystemTick()) / 1000000ULL;
}

/*
 * Appends one line and closes the file again.
 *
 * Holding the log open meant that a console powered off at the wall left the
 * directory entry stale and the tail of the file unwritten - which is how a
 * black screen at boot became impossible to diagnose. Reopening per line
 * costs nothing at the rate we log and guarantees that whatever reached the
 * card is really there.
 */
static void logf(const char *fmt, ...)
{
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fclose(f);
}

/* awg_config_dump writes through a FILE*, so hand it one briefly. */
static void awg_config_dump_log(const awg_config *cfg)
{
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    awg_config_dump(cfg, f);
    fclose(f);
}

/* ------------------------------------------------------------- http probe */

/*
 * The smallest thing that exercises TCP end to end. 1.1.1.1 is used because
 * its address never changes - resolving a name would drag DNS into a test
 * that is meant to be about TCP.
 */
typedef enum {
    HTTP_IDLE = 0, HTTP_CONNECTING, HTTP_SENT, HTTP_GOT_DATA, HTTP_DONE, HTTP_FAILED
} http_state;

static http_state      g_http = HTTP_IDLE;
static struct tcp_pcb *g_pcb = NULL;
static uint32_t        g_http_bytes = 0;
static uint64_t        g_http_started = 0;
static uint32_t        g_http_ms = 0;
static char            g_http_line[64];
static int             g_http_err = 0;

static void http_reset(void)
{
    /* tcp_close can fail when the connection still owes data; abort is the
     * honest way to let go of one we no longer care about. */
    if (g_pcb) {
        tcp_arg(g_pcb, NULL);
        tcp_recv(g_pcb, NULL);
        tcp_err(g_pcb, NULL);
        tcp_abort(g_pcb);
        g_pcb = NULL;
    }
}

static err_t http_on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;

    if (p == NULL) {                 /* peer closed: the fetch is complete */
        g_http = (g_http_bytes > 0) ? HTTP_DONE : HTTP_FAILED;
        g_http_ms = (uint32_t)(now_ms() - g_http_started);
        return ERR_OK;
    }
    if (err != ERR_OK) { pbuf_free(p); g_http = HTTP_FAILED; return err; }

    /* Keep the status line from the first chunk; it is the proof. */
    if (g_http_bytes == 0) {
        u16_t n = p->tot_len < sizeof(g_http_line) - 1
                ? p->tot_len : (u16_t)(sizeof(g_http_line) - 1);
        pbuf_copy_partial(p, g_http_line, n, 0);
        g_http_line[n] = 0;
        for (char *c = g_http_line; *c; c++)
            if (*c == '\r' || *c == '\n') { *c = 0; break; }
    }

    g_http_bytes += p->tot_len;
    g_http = HTTP_GOT_DATA;
    g_http_ms = (uint32_t)(now_ms() - g_http_started);

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void http_on_err(void *arg, err_t err)
{
    (void)arg;
    /* lwIP has already freed the pcb by the time this runs. */
    g_pcb = NULL;
    g_http_err = (int)err;
    g_http = HTTP_FAILED;
}

static err_t http_on_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK) { g_http = HTTP_FAILED; g_http_err = (int)err; return err; }

    static const char req[] =
        "GET / HTTP/1.0\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n";

    tcp_recv(pcb, http_on_recv);
    if (tcp_write(pcb, req, sizeof(req) - 1, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        g_http = HTTP_FAILED;
        return ERR_MEM;
    }
    tcp_output(pcb);
    g_http = HTTP_SENT;
    return ERR_OK;
}

static bool http_start(void)
{
    http_reset();

    g_http_bytes   = 0;
    g_http_err     = 0;
    g_http_line[0] = 0;
    g_http_started = now_ms();

    g_pcb = tcp_new();
    if (!g_pcb) { g_http = HTTP_FAILED; return false; }

    tcp_err(g_pcb, http_on_err);

    ip_addr_t dst;
    IP4_ADDR(&dst, 1, 1, 1, 1);

    g_http = HTTP_CONNECTING;
    if (tcp_connect(g_pcb, &dst, 80, http_on_connected) != ERR_OK) {
        g_http = HTTP_FAILED;
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    mkdir(CFG_DIR, 0777);

    /* Start a fresh file, then never hold it open again - see logf(). */
    { FILE *f = fopen(LOG_PATH, "w"); if (!f) return 0; fclose(f); }

    logf("sys-amneziawg starting\n");
    logf("boot: module started\n");

    awg_config cfg;
    char err[256];
    if (awg_config_load(&cfg, CONF_PATH, err, sizeof(err)) != 0) {
        logf("config error: %s\n", err);
            return 0;
    }

    logf("boot: config loaded, waiting 15s to stay out of the boot's way\n");

    /* Let the console finish booting before touching services or the card. */
    svcSleepThread(15000000000ULL);

    logf("boot: waiting for the network\n");
    wait_for_network();
    logf("boot: network up\n");

    {
        time_t t = (time_t)awg_now_seconds();
        logf("console time: %s", ctime(&t));
    }

    u32 myip = 0;
    if (R_FAILED(nifmGetCurrentIpAddress(&myip)) || myip == 0) {
        logf("could not learn the console's own address\n");
        goto done;
    }
    {
        struct in_addr a = { .s_addr = myip };
        char s[32]; inet_ntop(AF_INET, &a, s, sizeof(s));
        logf("console ip: %s\n", s);
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)cfg.endpoint_port);
    if (inet_pton(AF_INET, cfg.endpoint_host, &dst.sin_addr) != 1) {
        logf("endpoint '%s' is not a literal IPv4 address\n", cfg.endpoint_host);
        goto done;
    }
    logf("endpoint: %s:%d\n", cfg.endpoint_host, cfg.endpoint_port);

    /*
     * Stage 6 probe: IPv6.
     *
     * Atmosphere's hosts files are IPv4 only, so if an application can reach
     * a AAAA record on its own it leaves through the front door and we never
     * see it. Whether that is a real hole or a theoretical one depends on
     * whether this console has IPv6 connectivity at all, which nobody has
     * checked. Opening the socket costs nothing and settles it.
     */
    {
        int p6 = socket(AF_INET6, SOCK_STREAM, 0);
        if (p6 < 0) {
            logf("probe ipv6: socket() refused (errno=%d) - no IPv6 stack\n", errno);
        } else {
            struct sockaddr_in6 s6;
            memset(&s6, 0, sizeof(s6));
            s6.sin6_family = AF_INET6;
            s6.sin6_port   = htons(80);
            /* 2606:4700:4700::1111, Cloudflare's resolver. */
            static const uint8_t cf[16] = {
                0x26,0x06,0x47,0x00,0x47,0x00,0,0,0,0,0,0,0,0,0x11,0x11
            };
            memcpy(&s6.sin6_addr, cf, sizeof(cf));

            /* Non-blocking, with a hard 3s ceiling: a blocking connect to an
             * address with no route can sit there for the whole TCP timeout,
             * and this runs before the tunnel comes up. A probe must never be
             * able to delay the module. */
            int fl = fcntl(p6, F_GETFL, 0);
            if (fl >= 0) fcntl(p6, F_SETFL, fl | O_NONBLOCK);

            int r = connect(p6, (struct sockaddr *)&s6, sizeof(s6));
            int e = errno;
            if (r < 0 && e == EINPROGRESS) {
                struct pollfd pf = { .fd = p6, .events = POLLOUT };
                if (poll(&pf, 1, 3000) > 0) {
                    int so = 0; socklen_t sl = sizeof(so);
                    if (getsockopt(p6, SOL_SOCKET, SO_ERROR, &so, &sl) == 0) {
                        r = so == 0 ? 0 : -1;
                        e = so;
                    }
                } else {
                    e = ETIMEDOUT;
                }
            }
            logf("probe ipv6: socket ok, connect=%d errno=%d%s\n",
                    r, r < 0 ? e : 0,
                    r == 0 ? "  <-- IPv6 REACHABLE, traffic can bypass us" : "");
            close(p6);
        }
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { logf("socket() failed errno=%d\n", errno); goto done; }

    awg_session sess;
    awg_session_init(&sess, &cfg);
    logf("timers: rekey %ds, keepalive %ds, retry %ds\n\n",
            sess.rekey_after_s, sess.keepalive_s, sess.rekey_timeout_s);

    uint64_t start = now_ms();
    uint64_t wall_at_start = awg_now_seconds();
    uint64_t next_fetch = 0, next_status = 0;

    uint32_t fetches = 0, fetches_ok = 0;
    bool netif_up = false;

    while (!g_stop) {
        uint64_t now = now_ms();

        /*
         * Resume detection by watching the clock rather than subscribing to
         * power events. Registering with psc:m put this module in the path of
         * every power transition and hung the console; a comparison costs
         * nothing and cannot wedge anything.
         */
        uint64_t wall = awg_now_seconds();
        int64_t drift = (int64_t)(wall - wall_at_start) - (int64_t)((now - start) / 1000);
        if (drift > 30) {
            logf("[%3us] resumed after ~%llds asleep - reconnecting\n",
                    (uint32_t)((now - start) / 1000), (long long)drift);
            awg_session_init(&sess, &cfg);
            http_reset();
            g_http = HTTP_IDLE;
            wall_at_start = wall - (now - start) / 1000;
            next_fetch = 0;
        }

        if (awg_session_needs_handshake(&sess, &cfg, now)) {
            int n = awg_session_build_initiation(&sess, &cfg, g_wire,
                                                 (int)sizeof(g_wire), now);
            if (n > 0) {
                static uint8_t junk[16 * 128];
                int jlens[16];
                int jn = awg_junk_packets(&cfg, junk, 128, jlens, 16);
                for (int j = 0; j < jn; j++)
                    sendto(fd, junk + j * 128, (size_t)jlens[j], 0,
                           (struct sockaddr *)&dst, sizeof(dst));

                int sr = sendto(fd, g_wire, (size_t)n, 0,
                                (struct sockaddr *)&dst, sizeof(dst));
                logf("[%3us] handshake %s attempt %d: sendto=%d\n",
                        (uint32_t)((now - start) / 1000),
                        sess.established ? "rekey" : "initial",
                        sess.handshake_tries, sr);
            }
        } else if (awg_session_needs_keepalive(&sess, now)) {
            int n = awg_session_build_keepalive(&sess, &cfg, g_wire,
                                                (int)sizeof(g_wire), now);
            if (n > 0)
                sendto(fd, g_wire, (size_t)n, 0, (struct sockaddr *)&dst, sizeof(dst));
        }

        /* Bring the stack up once there is a session for it to sit on. */
        if (sess.established && !netif_up) {
            if (awg_netif_start(&cfg, &sess, fd, &dst, (int)sizeof(dst)) == 0) {
                netif_up = true;
                logf("[%3us] lwip interface up on the tunnel\n",
                        (uint32_t)((now - start) / 1000));

                uint32_t resolver = cfg.dns_n > 1 ? cfg.dns[1] : cfg.dns[0];
                if (awg_proxy_start(443, resolver, LOG_PATH) == 0)
                    logf("[%3us] proxy listening on 127.0.0.1:443\n",
                            (uint32_t)((now - start) / 1000));
                else
                    logf("[%3us] proxy FAILED to bind :443 (errno=%d)\n",
                            (uint32_t)((now - start) / 1000), errno);
            } else {
                logf("[%3us] lwip interface FAILED to start\n",
                        (uint32_t)((now - start) / 1000));
            }
        }

        bool busy = (g_http == HTTP_CONNECTING || g_http == HTTP_SENT ||
                     g_http == HTTP_GOT_DATA);
        if (netif_up && sess.established && !busy && now >= next_fetch) {
            fetches++;
            logf("[%3us] fetch %u: connecting to 1.1.1.1:80\n",
                    (uint32_t)((now - start) / 1000), fetches);
            http_start();
            next_fetch = now + FETCH_EVERY_MS;
        }

        /* Report a finished fetch exactly once. */
        if (g_http == HTTP_DONE || g_http == HTTP_FAILED) {
            if (g_http == HTTP_DONE) {
                fetches_ok++;
                logf("        got %u bytes in %ums: \"%s\"\n",
                        g_http_bytes, g_http_ms, g_http_line);
            } else {
                logf("        FAILED (lwip err %d, %u bytes)\n",
                        g_http_err, g_http_bytes);
            }
            http_reset();
            g_http = HTTP_IDLE;
        }

        /*
         * Drain the socket, do not sip from it. Taking a single datagram per
         * pass capped the tunnel at roughly fifty packets a second, which was
         * invisible while we only sent a DNS probe every ten seconds and
         * became a wall the moment something tried to download.
         */
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, 1) > 0) {
            for (int drained = 0; drained < 64; drained++) {
                int rn = (int)recv(fd, g_rx, sizeof(g_rx), MSG_DONTWAIT);
                if (rn <= 0) break;

                int plen = 0;
                uint64_t t = now_ms();
                awg_rx_result r = awg_session_on_datagram(&sess, &cfg, g_rx, rn,
                                                          g_inner, (int)sizeof(g_inner),
                                                          &plen, t);
                if (r == AWG_RX_ESTABLISHED) {
                    logf("[%3us] session up (handshake #%u, rekeys %u)\n",
                            (uint32_t)((t - start) / 1000),
                            sess.handshakes_done, sess.rekeys);
                } else if (r == AWG_RX_PAYLOAD) {
                    awg_netif_input(g_inner, plen);
                }
            }
        }

        /* lwIP has no thread of its own; its timers only run when we ask. */
        awg_netif_poll();

        if (netif_up) awg_proxy_poll(1);

        if (now_ms() >= next_status) {
            uint64_t t = now_ms();
            awg_proxy_stats ps;
            awg_proxy_get_stats(&ps);

            /* Rates, not totals: a total tells you nothing about whether the
             * transfer is moving now. */
            static uint32_t last_rx_pkts = 0, last_down_kb = 0;
            uint32_t d_pkts = sess.packets_rx - last_rx_pkts;
            uint32_t d_kb   = (uint32_t)(ps.bytes_down / 1024) - last_down_kb;
            last_rx_pkts = sess.packets_rx;
            last_down_kb = (uint32_t)(ps.bytes_down / 1024);
            logf("[%3us] up=%us tx=%u rx=%u ka=%u fetches %u/%u | "
                         "proxy conns=%u ok=%u fail=%u closed=%u live=%u/%u "
                         "deny=%u full=%u idle=%u up=%lluKB down=%lluKB\n",
                    (uint32_t)((t - start) / 1000),
                    awg_session_age_s(&sess, t),
                    sess.packets_tx, sess.packets_rx, sess.keepalives_tx,
                    fetches_ok, fetches,
                    ps.accepted, ps.completed, ps.failed, ps.closed,
                    awg_proxy_live(), (uint32_t)AWG_PROXY_MAX_CONN,
                    ps.denied, ps.refused, ps.timed_out,
                    (unsigned long long)(ps.bytes_up / 1024),
                    (unsigned long long)(ps.bytes_down / 1024));

            /*
             * Only once lwIP is actually running: its statistics pointers are
             * filled in by lwip_init(), which does not happen until there is
             * a session for the interface to sit on. Reading them before that
             * dereferences a null pointer, which is precisely how this line
             * crashed the module the first time round.
             */
            if (netif_up) {
                const struct stats_mem *pool = lwip_stats.memp[MEMP_PBUF_POOL];

                /* xmit far above recv means we are retransmitting, which is
                 * what packet loss looks like from in here. memerr and the
                 * pbuf pool errors say whether we simply ran out of buffers
                 * instead. */
                logf("        rate %uKB/s (%u pkt/s) | tcp xmit=%u recv=%u "
                             "drop=%u memerr=%u | ip drop=%u | pbuf err=%u\n",
                        d_kb / 15, d_pkts / 15,
                        (unsigned)lwip_stats.tcp.xmit,
                        (unsigned)lwip_stats.tcp.recv,
                        (unsigned)lwip_stats.tcp.drop,
                        (unsigned)lwip_stats.tcp.memerr,
                        (unsigned)lwip_stats.ip.drop,
                        pool ? (unsigned)pool->err : 0u);
            } else {
                logf("        rate %uKB/s (%u pkt/s) | stack not up yet\n",
                        d_kb / 15, d_pkts / 15);
            }
            next_status = t + 15000;
        }
    }

    http_reset();
    awg_proxy_stop();
    close(fd);

    logf("\n=== summary ===\n");
    logf("ran %us\n", (uint32_t)((now_ms() - start) / 1000));
    logf("handshakes %u (rekeys %u)\n", sess.handshakes_done, sess.rekeys);
    logf("tunnel packets tx=%u rx=%u\n", sess.packets_tx, sess.packets_rx);
    logf("http fetches %u attempted, %u succeeded\n", fetches, fetches_ok);

    logf("\n=== verdict ===\n");
    if (fetches_ok == 0)
        logf("TCP does not work over the tunnel yet.\n");
    else if (fetches_ok == fetches)
        logf("A full TCP/IP stack now runs over the tunnel.\n");
    else
        logf("TCP works but is unreliable - see the failures above.\n");

done:
    awg_config_free(&cfg);
    logf("\ndone.\n");

    while (!g_stop) svcSleepThread(10000000000ULL);
    return 0;
}
