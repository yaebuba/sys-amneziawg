/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Transparent TLS proxy over the tunnel. See awg_proxy.h for the idea.
 *
 * The awkward part is that two event systems meet here. The console side is
 * ordinary BSD sockets that we poll; the tunnel side is lwIP's raw API, which
 * is callback-driven and must only be touched from the same thread that ticks
 * it. Both are driven from one loop, and every buffer below exists to bridge
 * that gap: bytes are parked until the other side is ready to take them.
 */
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "awg_proxy.h"

#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"

#define MAX_CONN 16
#define BUF_SIZE 8192

/* A ClientHello that has not produced a hostname by this many bytes is not
 * going to; something other than TLS is talking to us. */
#define SNIFF_LIMIT 2048

typedef enum {
    ST_FREE = 0,
    ST_SNIFF,       /* reading the ClientHello, looking for the hostname */
    ST_RESOLVING,   /* waiting on DNS, which itself goes through the tunnel */
    ST_CONNECTING,  /* lwIP is opening the outbound connection             */
    ST_RELAY        /* both halves are up; move bytes                      */
} cstate;

typedef struct {
    cstate st;
    int    cfd;                 /* the application's socket, console side */
    struct tcp_pcb *pcb;        /* the real connection, tunnel side       */

    char   host[128];

    uint8_t up[BUF_SIZE];       /* console -> tunnel, awaiting send       */
    int     up_len;

    /*
     * The downstream direction holds lwIP's own pbufs rather than copying
     * into a buffer of our own, and acknowledges them only once the bytes
     * have reached the application.
     *
     * That ordering is the whole point. Copying into a fixed buffer meant
     * refusing data with ERR_MEM when it filled, and lwIP responds to a
     * refusal by parking one segment and dropping every one that follows
     * until the parked one is taken - with no window update, so the sender
     * simply stops. Holding the chain instead lets the receive window close
     * naturally, which is how TCP is supposed to say "slow down".
     */
    struct pbuf *rx_head;
    u16_t        rx_off;        /* bytes of rx_head already handed over    */

    bool    peer_closed;        /* the remote end finished sending        */
} conn_t;

static conn_t  g_conn[MAX_CONN];
static int     g_listen = -1;
static uint32_t g_dns_server;
static const char *g_log_path;
static awg_proxy_stats g_stats;

static void logp(const char *fmt, ...)
{
    if (!g_log_path) return;
    FILE *f = fopen(g_log_path, "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}
#define LOGP(...) logp(__VA_ARGS__)

/* ------------------------------------------------------------ ClientHello */

/*
 * Locates the server name inside a TLS ClientHello. Lifted from sys-dpi,
 * where it earned its keep: the record layout is fixed, so this is a walk
 * through known offsets rather than a parser.
 */
static int find_sni(const uint8_t *b, int len, int *out_len)
{
    int p;
    if (len < 45)     return -1;
    if (b[0] != 0x16) return -1;    /* handshake record */
    if (b[5] != 0x01) return -1;    /* ClientHello      */

    p = 43;
    if (p + 1 > len) return -1;
    p += 1 + b[p];                                   /* session id  */
    if (p + 2 > len) return -1;
    p += 2 + ((b[p] << 8) | b[p + 1]);               /* cipher list */
    if (p + 1 > len) return -1;
    p += 1 + b[p];                                   /* compression */
    if (p + 2 > len) return -1;

    int ext_total = (b[p] << 8) | b[p + 1];
    p += 2;
    int end = p + ext_total;
    if (end > len) end = len;

    while (p + 4 <= end) {
        int type = (b[p] << 8) | b[p + 1];
        int elen = (b[p + 2] << 8) | b[p + 3];
        p += 4;
        if (p + elen > end) return -1;
        if (type == 0x0000) {                        /* server_name */
            int q = p;
            if (q + 2 > end) return -1;
            q += 2;
            if (q + 3 > end) return -1;
            if (b[q] != 0) return -1;                /* host_name type */
            int nlen = (b[q + 1] << 8) | b[q + 2];
            q += 3;
            if (q + nlen > end || nlen <= 0) return -1;
            *out_len = nlen;
            return q;
        }
        p += elen;
    }
    return -1;
}

static int sni_hostname(const uint8_t *b, int len, char *out, int cap)
{
    int nlen = 0;
    int off = find_sni(b, len, &nlen);
    if (off < 0 || nlen >= cap) return -1;
    memcpy(out, b + off, (size_t)nlen);
    out[nlen] = 0;
    return nlen;
}

/* ----------------------------------------------------------- connections */

static void conn_close(conn_t *c, const char *why)
{
    if (c->st == ST_FREE) return;

    if (c->pcb) {
        tcp_arg(c->pcb, NULL);
        tcp_recv(c->pcb, NULL);
        tcp_sent(c->pcb, NULL);
        tcp_err(c->pcb, NULL);
        /* abort rather than close: close can fail and leave the pcb behind,
         * and by this point we have nothing left to say. */
        tcp_abort(c->pcb);
        c->pcb = NULL;
    }
    if (c->rx_head) { pbuf_free(c->rx_head); c->rx_head = NULL; c->rx_off = 0; }
    if (c->cfd >= 0) { close(c->cfd); c->cfd = -1; }

    if (why && c->host[0]) LOGP("        proxy: %s (%s)\n", c->host, why);

    memset(c, 0, sizeof(*c));
    c->cfd = -1;
    c->st  = ST_FREE;
}

static conn_t *conn_alloc(void)
{
    for (int i = 0; i < MAX_CONN; i++)
        if (g_conn[i].st == ST_FREE) {
            memset(&g_conn[i], 0, sizeof(conn_t));
            g_conn[i].cfd = -1;
            return &g_conn[i];
        }
    return NULL;
}

static void set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* --------------------------------------------------------- lwIP callbacks */

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    conn_t *c = (conn_t *)arg;
    if (!c) { if (p) pbuf_free(p); return ERR_OK; }

    (void)pcb;

    if (p == NULL) {              /* remote finished sending */
        c->peer_closed = true;
        return ERR_OK;
    }
    if (err != ERR_OK) { pbuf_free(p); return err; }

    /* Always accept. The window, not a refusal, is what throttles the peer. */
    if (c->rx_head) pbuf_cat(c->rx_head, p);
    else            c->rx_head = p;

    return ERR_OK;
}

static void on_err(void *arg, err_t err)
{
    conn_t *c = (conn_t *)arg;
    if (!c) return;
    /* lwIP has already freed the pcb. */
    c->pcb = NULL;
    g_stats.failed++;
    LOGP("        proxy: %s failed (lwip err %d)\n", c->host, (int)err);
    conn_close(c, NULL);
}

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    conn_t *c = (conn_t *)arg;
    if (!c) return ERR_ABRT;

    if (err != ERR_OK) { g_stats.failed++; conn_close(c, "connect failed"); return err; }

    tcp_recv(pcb, on_recv);
    c->st = ST_RELAY;
    g_stats.connected++;
    return ERR_OK;
}

static void on_resolved(const char *name, const ip_addr_t *ip, void *arg)
{
    (void)name;
    conn_t *c = (conn_t *)arg;
    if (!c || c->st != ST_RESOLVING) return;

    if (!ip) { g_stats.failed++; conn_close(c, "dns failed"); return; }

    g_stats.resolved++;

    c->pcb = tcp_new();
    if (!c->pcb) { g_stats.failed++; conn_close(c, "no pcb"); return; }

    tcp_arg(c->pcb, c);
    tcp_err(c->pcb, on_err);

    c->st = ST_CONNECTING;
    if (tcp_connect(c->pcb, ip, 443, on_connected) != ERR_OK) {
        g_stats.failed++;
        conn_close(c, "connect refused locally");
    }
}

/* ------------------------------------------------------------------ pump */

/* Moves whatever the console has said into the tunnel. */
static void pump_up(conn_t *c)
{
    if (c->up_len <= 0 || !c->pcb) return;

    u16_t room = tcp_sndbuf(c->pcb);
    if (room == 0) return;                       /* try again next tick */

    int n = c->up_len < room ? c->up_len : room;
    if (tcp_write(c->pcb, c->up, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) return;
    tcp_output(c->pcb);

    memmove(c->up, c->up + n, (size_t)(c->up_len - n));
    c->up_len -= n;
    g_stats.bytes_up += (uint32_t)n;
}

/* And whatever came back into the application's socket. */
static void pump_down(conn_t *c)
{
    while (c->rx_head) {
        struct pbuf *p = c->rx_head;
        int avail = p->len - c->rx_off;

        if (avail <= 0) {                    /* this link is spent */
            /* Detach before freeing. pbuf_cat handed us ownership of the
             * whole chain with one reference each, so taking an extra
             * reference on the next link here would leak it and starve the
             * pool a few hundred packets later. */
            struct pbuf *next = p->next;
            p->next = NULL;
            pbuf_free(p);
            c->rx_head = next;
            c->rx_off  = 0;
            continue;
        }

        int n = (int)send(c->cfd, (uint8_t *)p->payload + c->rx_off, (size_t)avail, 0);
        if (n > 0) {
            c->rx_off += (u16_t)n;
            g_stats.bytes_down += (uint32_t)n;
            /* Acknowledge only now: the window reopens exactly as fast as the
             * application drinks, which is the flow control we want. */
            if (c->pcb) tcp_recved(c->pcb, (u16_t)n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        conn_close(c, "client write failed");
        return;
    }
}

static void handle_client_readable(conn_t *c)
{
    int space = BUF_SIZE - c->up_len;
    if (space <= 0) return;                      /* tunnel side is behind */

    int n = (int)recv(c->cfd, c->up + c->up_len, (size_t)space, 0);
    if (n == 0) {
        /* The application is done sending. Anything already buffered still
         * needs to go, so let the relay drain rather than closing here. */
        if (c->pcb && c->up_len == 0) tcp_shutdown(c->pcb, 0, 1);
        return;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        conn_close(c, "client read failed");
        return;
    }

    c->up_len += n;

    if (c->st == ST_SNIFF) {
        if (sni_hostname(c->up, c->up_len, c->host, sizeof(c->host)) > 0) {
            LOGP("        proxy: %s\n", c->host);

            ip_addr_t ip;
            c->st = ST_RESOLVING;
            err_t r = dns_gethostbyname(c->host, &ip, on_resolved, c);
            if (r == ERR_OK)            on_resolved(c->host, &ip, c);
            else if (r != ERR_INPROGRESS) { g_stats.failed++; conn_close(c, "dns rejected"); }
        } else if (c->up_len >= SNIFF_LIMIT) {
            conn_close(c, "no SNI found");
        }
    }
}

/* ------------------------------------------------------------------- api */

int awg_proxy_start(uint32_t bind_ip, uint16_t port, uint32_t dns_server,
                    const char *log_path)
{
    g_log_path   = log_path;
    g_dns_server = dns_server;
    memset(&g_stats, 0, sizeof(g_stats));

    for (int i = 0; i < MAX_CONN; i++) { g_conn[i].st = ST_FREE; g_conn[i].cfd = -1; }

    /* Point lwIP's resolver at the configured server; the query travels down
     * the tunnel like everything else. */
    ip_addr_t dns;
    dns.addr = dns_server;
    dns_setserver(0, &dns);

    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen < 0) return -1;

    int yes = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = bind_ip;    /* never INADDR_ANY: Horizon will not
                                      * deliver connections to it */

    if (bind(g_listen, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(g_listen); g_listen = -1; return -1;
    }
    if (listen(g_listen, MAX_CONN) < 0) {
        close(g_listen); g_listen = -1; return -1;
    }
    set_nonblock(g_listen);
    return 0;
}

void awg_proxy_poll(int timeout_ms)
{
    if (g_listen < 0) return;

    struct pollfd fds[MAX_CONN + 1];
    conn_t *owner[MAX_CONN + 1];
    int nf = 0;

    fds[nf].fd = g_listen; fds[nf].events = POLLIN; fds[nf].revents = 0;
    owner[nf] = NULL;
    nf++;

    for (int i = 0; i < MAX_CONN; i++) {
        conn_t *c = &g_conn[i];
        if (c->st == ST_FREE || c->cfd < 0) continue;

        short ev = 0;
        if (BUF_SIZE - c->up_len > 0) ev |= POLLIN;
        if (c->rx_head)               ev |= POLLOUT;
        if (!ev) continue;

        fds[nf].fd = c->cfd; fds[nf].events = ev; fds[nf].revents = 0;
        owner[nf] = c;
        nf++;
    }

    if (poll(fds, (nfds_t)nf, timeout_ms) > 0) {
        if (fds[0].revents & POLLIN) {
            int cfd = accept(g_listen, NULL, NULL);
            if (cfd >= 0) {
                conn_t *c = conn_alloc();
                if (!c) {
                    close(cfd);              /* table full: refuse politely */
                } else {
                    set_nonblock(cfd);
                    c->cfd = cfd;
                    c->st  = ST_SNIFF;
                    g_stats.accepted++;
                }
            }
        }

        for (int i = 1; i < nf; i++) {
            conn_t *c = owner[i];
            if (!c || c->st == ST_FREE) continue;
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                conn_close(c, "client hung up");
                continue;
            }
            if (fds[i].revents & POLLOUT) pump_down(c);
            if (c->st != ST_FREE && (fds[i].revents & POLLIN)) handle_client_readable(c);
        }
    }

    /* Regardless of poll: lwIP may have handed us data or freed send window
     * since the last pass. */
    for (int i = 0; i < MAX_CONN; i++) {
        conn_t *c = &g_conn[i];
        if (c->st == ST_FREE) continue;

        if (c->st == ST_RELAY) pump_up(c);
        if (c->rx_head)        pump_down(c);

        /* Finish only once the remote has closed and everything it sent has
         * reached the application. */
        if (c->peer_closed && !c->rx_head) {
            g_stats.completed++;
            conn_close(c, NULL);
        }
    }
}

void awg_proxy_stop(void)
{
    for (int i = 0; i < MAX_CONN; i++) conn_close(&g_conn[i], NULL);
    if (g_listen >= 0) { close(g_listen); g_listen = -1; }
}

void awg_proxy_get_stats(awg_proxy_stats *out)
{
    if (out) *out = g_stats;
}
