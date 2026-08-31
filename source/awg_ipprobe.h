/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * A single IPv4/UDP/DNS exchange, built by hand.
 *
 * Once the tunnel carries data it carries raw IP packets, not sockets, so to
 * prove the data path works we have to speak IP ourselves. A DNS query is the
 * smallest useful thing to send: one packet out, one packet back, and the
 * answer is self-validating - a wrong tunnel gives no reply at all rather
 * than a plausible-looking wrong one.
 *
 * This is throwaway scaffolding for stage 2. Once lwIP is in place it takes
 * over all of this.
 */
#ifndef SYS_AWG_IPPROBE_H
#define SYS_AWG_IPPROBE_H

#include <stdint.h>

/*
 * Builds an IPv4 datagram carrying a UDP DNS A-query for `host`.
 * Addresses are in network order. Returns the total length or -1.
 */
int ipprobe_build_dns(uint8_t *out, int cap,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t src_port, uint16_t txid, const char *host);

/*
 * Checks that `pkt` is the matching DNS reply and extracts the first A
 * record. Returns 0 on success, or a negative code identifying how far the
 * packet got - which is the useful part when a tunnel half works:
 *
 *   -1 too short   -2 not IPv4   -3 not UDP     -4 wrong addresses
 *   -5 wrong port  -6 bad DNS    -7 wrong txid  -8 no A record
 */
int ipprobe_parse_dns(const uint8_t *pkt, int len,
                      uint32_t expect_src_ip, uint16_t expect_dst_port,
                      uint16_t txid, uint32_t *answer_ip);

/* Renders an IPv4 address into "a.b.c.d". */
void ipprobe_ip_str(uint32_t net_order, char *out, int cap);

#endif /* SYS_AWG_IPPROBE_H */
