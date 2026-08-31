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
 * Binds the listener. `bind_ip` is the console's own LAN address in network
 * order - Horizon does not deliver connections to a socket bound to
 * INADDR_ANY, so the address has to be the specific one dns.mitm points at.
 *
 * Returns 0 on success.
 */
/* `log_path` is reopened per line rather than held: a console powered off at
 * the wall must not take the tail of the log with it. */
int awg_proxy_start(uint32_t bind_ip, uint16_t port, uint32_t dns_server,
                    const char *log_path);

/*
 * Drives the proxy: accepts new connections, moves bytes in both directions.
 * Call it from the main loop alongside awg_netif_poll(). Never blocks for
 * longer than `timeout_ms`.
 */
void awg_proxy_poll(int timeout_ms);

void awg_proxy_stop(void);

/* Counters for the log. */
typedef struct {
    uint32_t accepted;
    uint32_t resolved;
    uint32_t connected;
    uint32_t completed;
    uint32_t failed;
    uint64_t bytes_up;
    uint64_t bytes_down;
} awg_proxy_stats;

void awg_proxy_get_stats(awg_proxy_stats *out);

#endif /* SYS_AWG_PROXY_H */
