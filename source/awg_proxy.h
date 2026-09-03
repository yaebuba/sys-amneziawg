/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * A transparent TLS proxy that carries connections through the tunnel.
 *
 * This is the step before intercepting sockets outright. dns.mitm points a
 * few hostnames at the console's own address, we accept the connection the
 * application makes, read the hostname out of its TLS ClientHello, and open
 * the real connection through lwIP - which means through the tunnel.
 *
 * The application is none the wiser: it thinks it opened a socket to GitHub
 * and got GitHub. The blast radius is limited to the hostnames listed in the
 * hosts file, which is the point of doing this before touching bsd:u.
 */
#ifndef SYS_AWG_PROXY_H
#define SYS_AWG_PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Binds the listener on 127.0.0.1, where hosts files should point.
 *
 * Horizon delivers cross-process connections to loopback, and that address
 * is the same on every network - which is what makes the dock, a new DHCP
 * lease and a phone hotspot survivable. `bind_ip`, the console's LAN
 * address, is gone from the signature: binding it turned the console into
 * an open proxy for everything else on the same Wi-Fi. The rest of 127.0.0.0/8 is
 * not available; Horizon gives loopback exactly one address.
 *
 * Returns 0 on success.
 */
/* `log_path` is reopened per line rather than held: a console powered off at
 * the wall must not take the tail of the log with it. */
int awg_proxy_start(uint16_t port, uint32_t dns_server,
                    const char *log_path);

/*
 * Drives the proxy: accepts new connections, moves bytes in both directions.
 * Call it from the main loop alongside awg_netif_poll(). Never blocks for
 * longer than `timeout_ms`.
 */
void awg_proxy_poll(int timeout_ms);

/* Slots currently in use, out of the fixed table. */
uint32_t awg_proxy_live(void);

/* Table size, so the log can print occupancy as a fraction. */
#define AWG_PROXY_MAX_CONN 16

void awg_proxy_stop(void);

/* Counters for the log. */
typedef struct {
    uint32_t accepted;
    uint32_t denied;        /* refused by the hostname deny list */
    uint32_t refused;       /* turned away because the table was full */
    uint32_t timed_out;     /* reclaimed by the idle sweep */
    /* Every close that was not a clean finish: the client hung up, a read or
     * write failed, the deny list or the idle sweep took it. Without this,
     * accepted - completed - failed looks like a leak when it is not. */
    uint32_t closed;
    uint32_t resolved;
    uint32_t connected;
    uint32_t completed;
    uint32_t failed;
    uint64_t bytes_up;
    uint64_t bytes_down;
} awg_proxy_stats;

void awg_proxy_get_stats(awg_proxy_stats *out);

#endif /* SYS_AWG_PROXY_H */
