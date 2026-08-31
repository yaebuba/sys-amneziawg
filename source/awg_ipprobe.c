/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Hand-rolled IPv4/UDP/DNS, for proving the tunnel's data path. See the
 * header for why this exists and when it goes away.
 *
 * No platform networking headers: this compiles for the console and the host
 * alike, and byte order is handled explicitly rather than via htons().
 */
#include <string.h>
#include <stdio.h>

#include "awg_ipprobe.h"

#define IP_HDR  20
#define UDP_HDR 8

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get_be16(const uint8_t *p)   { return (uint16_t)((p[0] << 8) | p[1]); }

/* One's complement sum, as every IP checksum needs. */
static uint32_t sum16(const uint8_t *p, int len, uint32_t acc)
{
    while (len > 1) { acc += get_be16(p); p += 2; len -= 2; }
    if (len) acc += (uint32_t)p[0] << 8;      /* odd trailing byte, high half */
    return acc;
}

static uint16_t fold(uint32_t acc)
{
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

/* encode "a.b.com" -> 1a1b3com0 ; returns bytes written or -1 */
static int encode_name(uint8_t *o, int cap, const char *host)
{
    int n = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len <= 0 || len > 63 || n + len + 1 >= cap) return -1;
        o[n++] = (uint8_t)len;
        memcpy(o + n, p, (size_t)len);
        n += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (n + 1 > cap) return -1;
    o[n++] = 0;
    return n;
}

/* Skips a possibly compressed name, returning the next offset or -1. */
static int skip_name(const uint8_t *b, int len, int off)
{
    while (off < len) {
        uint8_t l = b[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return (off + 2 <= len) ? off + 2 : -1;
        off += 1 + l;
    }
    return -1;
}

int ipprobe_build_dns(uint8_t *out, int cap,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t src_port, uint16_t txid, const char *host)
{
    if (cap < IP_HDR + UDP_HDR + 32) return -1;

    uint8_t *dns = out + IP_HDR + UDP_HDR;
    int dns_cap = cap - IP_HDR - UDP_HDR;

    put_be16(dns + 0, txid);
    dns[2] = 0x01; dns[3] = 0x00;          /* recursion desired */
    put_be16(dns + 4, 1);                  /* qdcount */
    memset(dns + 6, 0, 6);
    int dn = 12;

    int nl = encode_name(dns + dn, dns_cap - dn - 4, host);
    if (nl < 0) return -1;
    dn += nl;
    put_be16(dns + dn, 1); dn += 2;        /* A     */
    put_be16(dns + dn, 1); dn += 2;        /* IN    */

    int udp_len   = UDP_HDR + dn;
    int total_len = IP_HDR + udp_len;

    /* IPv4 header */
    out[0] = 0x45;                          /* version 4, 5 words */
    out[1] = 0;                             /* DSCP/ECN */
    put_be16(out + 2, (uint16_t)total_len);
    put_be16(out + 4, txid);                /* identification */
    put_be16(out + 6, 0x4000);              /* don't fragment */
    out[8]  = 64;                           /* TTL */
    out[9]  = 17;                           /* UDP */
    out[10] = out[11] = 0;                  /* checksum, filled below */
    memcpy(out + 12, &src_ip, 4);
    memcpy(out + 16, &dst_ip, 4);
    put_be16(out + 10, fold(sum16(out, IP_HDR, 0)));

    /* UDP header */
    uint8_t *udp = out + IP_HDR;
    put_be16(udp + 0, src_port);
    put_be16(udp + 2, 53);
    put_be16(udp + 4, (uint16_t)udp_len);
    udp[6] = udp[7] = 0;

    /* UDP checksum covers a pseudo-header of the addresses, protocol and
     * length. It is optional in IPv4, but WireGuard peers hand packets to a
     * real stack that may well drop a zero-checksum datagram. */
    uint32_t acc = 0;
    acc = sum16((const uint8_t *)&src_ip, 4, acc);
    acc = sum16((const uint8_t *)&dst_ip, 4, acc);
    acc += 17;
    acc += (uint32_t)udp_len;
    acc = sum16(udp, udp_len, acc);
    uint16_t ck = fold(acc);
    if (ck == 0) ck = 0xFFFF;               /* 0 means "no checksum" */
    put_be16(udp + 6, ck);

    return total_len;
}

int ipprobe_parse_dns(const uint8_t *pkt, int len,
                      uint32_t expect_src_ip, uint16_t expect_dst_port,
                      uint16_t txid, uint32_t *answer_ip)
{
    if (len < IP_HDR + UDP_HDR + 12) return -1;
    if ((pkt[0] >> 4) != 4) return -2;

    int ihl = (pkt[0] & 0x0F) * 4;
    if (ihl < IP_HDR || len < ihl + UDP_HDR) return -1;
    if (pkt[9] != 17) return -3;

    uint32_t src;
    memcpy(&src, pkt + 12, 4);
    if (src != expect_src_ip) return -4;

    const uint8_t *udp = pkt + ihl;
    if (get_be16(udp + 2) != expect_dst_port) return -5;

    int udp_len = get_be16(udp + 4);
    if (udp_len < UDP_HDR || ihl + udp_len > len) return -6;

    const uint8_t *d = udp + UDP_HDR;
    int dn = udp_len - UDP_HDR;
    if (dn < 12) return -6;

    if (get_be16(d) != txid) return -7;

    int ancount = get_be16(d + 6);
    int off = skip_name(d, dn, 12);
    if (off < 0) return -6;
    off += 4;                                /* qtype + qclass */

    for (int i = 0; i < ancount && off + 10 <= dn; i++) {
        off = skip_name(d, dn, off);
        if (off < 0 || off + 10 > dn) break;
        int type  = get_be16(d + off);
        int rdlen = get_be16(d + off + 8);
        off += 10;
        if (off + rdlen > dn) break;
        if (type == 1 && rdlen == 4) {
            memcpy(answer_ip, d + off, 4);
            return 0;
        }
        off += rdlen;                        /* CNAME and friends */
    }
    return -8;
}

void ipprobe_ip_str(uint32_t net_order, char *out, int cap)
{
    const uint8_t *b = (const uint8_t *)&net_order;
    snprintf(out, (size_t)cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}
