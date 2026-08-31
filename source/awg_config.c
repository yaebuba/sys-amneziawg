/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * AmneziaWG .conf parser.
 *
 * Deliberately free of platform headers so the same file builds for Horizon:
 * addresses are parsed by hand rather than through inet_pton.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "awg.h"

/* I1 templates run well past a kilobyte, so lines cannot be small. */
#define LINE_MAX 8192

static void trim(char *s)
{
    char *p = s + strlen(s);
    while (p > s && (p[-1] == '\n' || p[-1] == '\r' || p[-1] == ' ' || p[-1] == '\t'))
        *--p = 0;
    while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
}

/* "1.2.3.4" -> network-order u32. Returns 0 on success. */
static int parse_ipv4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    int octet = 0, digits = 0, parts = 0;

    for (const char *p = s;; p++) {
        if (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            if (++digits > 3 || octet > 255) return -1;
        } else if (*p == '.' || *p == 0) {
            if (!digits) return -1;
            v = (v << 8) | (uint32_t)octet;
            parts++;
            octet = digits = 0;
            if (*p == 0) break;
            if (parts == 4) return -1;
        } else {
            return -1;
        }
    }
    if (parts != 4) return -1;

    /* Network order: first octet in the low byte on little-endian hosts. */
    *out = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
    return 0;
}

/* "100-120" or "25". A bare value collapses to a degenerate range. */
static void parse_range(const char *s, awg_range *r)
{
    char *end = NULL;
    long a = strtol(s, &end, 10);
    r->min = r->max = (int)a;
    if (end && *end == '-') {
        long b = strtol(end + 1, NULL, 10);
        if (b >= a) r->max = (int)b;
    }
}

static int parse_key(const char *b64, uint8_t *out, char *err, size_t errsz,
                     const char *what)
{
    int n = awg_b64_decode(b64, out, AWG_KEY_LEN);
    if (n != AWG_KEY_LEN) {
        snprintf(err, errsz, "%s is not a 32-byte base64 key", what);
        return -1;
    }
    return 0;
}

void awg_config_free(awg_config *cfg)
{
    for (int i = 0; i < AWG_MAX_I; i++) {
        awg_obf_free(cfg->i[i]);
        cfg->i[i] = NULL;
    }
}

int awg_config_load(awg_config *cfg, const char *path, char *err, size_t errsz)
{
    memset(cfg, 0, sizeof(*cfg));
    if (err && errsz) err[0] = 0;

    /* Defaults match plain WireGuard, so a config that omits the AmneziaWG
     * extensions still describes a working (unobfuscated) peer. */
    cfg->h1 = 1; cfg->h2 = 2; cfg->h3 = 3; cfg->h4 = 4;
    cfg->rekey_after_time.min       = cfg->rekey_after_time.max       = 120;
    cfg->rekey_timeout.min          = cfg->rekey_timeout.max          = 5;
    cfg->reject_after_time.min      = cfg->reject_after_time.max      = 180;
    cfg->keepalive_timeout.min      = cfg->keepalive_timeout.max      = 10;
    cfg->max_handshake_attempts.min = cfg->max_handshake_attempts.max = 18;

    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, errsz, "cannot open %s", path); return -1; }

    char *line = malloc(LINE_MAX);
    if (!line) { fclose(f); snprintf(err, errsz, "out of memory"); return -1; }

    int in_peer = 0, rc = 0, lineno = 0;

    while (fgets(line, LINE_MAX, f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        trim(line);
        if (!line[0]) continue;

        if (line[0] == '[') {
            in_peer = (strncmp(line, "[Peer", 5) == 0);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;

        /* Keys are base64 and contain '=' padding, so split on the first one
         * only and let the value keep the rest. */
        *eq = 0;
        char *k = line, *v = eq + 1;
        trim(k); trim(v);
        if (!*k) continue;

        char kerr[128] = {0};

        if (!in_peer) {
            if (!strcmp(k, "PrivateKey")) {
                if (parse_key(v, cfg->private_key, kerr, sizeof(kerr), "PrivateKey")) goto bad;
                cfg->have_private_key = true;
            } else if (!strcmp(k, "HeaderProtectionKey")) {
                if (parse_key(v, cfg->header_protection_key, kerr, sizeof(kerr),
                              "HeaderProtectionKey")) goto bad;
                cfg->have_header_protection = true;
            } else if (!strcmp(k, "Address")) {
                char *slash = strchr(v, '/');
                if (slash) { *slash = 0; cfg->address_cidr = atoi(slash + 1); }
                else cfg->address_cidr = 32;
                if (parse_ipv4(v, &cfg->address)) {
                    snprintf(kerr, sizeof(kerr), "Address is not IPv4");
                    goto bad;
                }
            } else if (!strcmp(k, "DNS")) {
                char *tok = strtok(v, ", ");
                while (tok && cfg->dns_n < 4) {
                    uint32_t ip;
                    if (parse_ipv4(tok, &ip) == 0) cfg->dns[cfg->dns_n++] = ip;
                    tok = strtok(NULL, ", ");
                }
            }
            else if (!strcmp(k, "Jc"))   cfg->jc   = atoi(v);
            else if (!strcmp(k, "Jmin")) cfg->jmin = atoi(v);
            else if (!strcmp(k, "Jmax")) cfg->jmax = atoi(v);
            else if (!strcmp(k, "S1"))   cfg->s1   = atoi(v);
            else if (!strcmp(k, "S2"))   cfg->s2   = atoi(v);
            else if (!strcmp(k, "S3"))   cfg->s3   = atoi(v);
            else if (!strcmp(k, "S4"))   cfg->s4   = atoi(v);
            else if (!strcmp(k, "H1"))   cfg->h1   = (uint32_t)strtoul(v, NULL, 10);
            else if (!strcmp(k, "H2"))   cfg->h2   = (uint32_t)strtoul(v, NULL, 10);
            else if (!strcmp(k, "H3"))   cfg->h3   = (uint32_t)strtoul(v, NULL, 10);
            else if (!strcmp(k, "H4"))   cfg->h4   = (uint32_t)strtoul(v, NULL, 10);
            else if (!strcmp(k, "RekeyAfterTime"))         parse_range(v, &cfg->rekey_after_time);
            else if (!strcmp(k, "RekeyTimeout"))           parse_range(v, &cfg->rekey_timeout);
            else if (!strcmp(k, "RejectAfterTime"))        parse_range(v, &cfg->reject_after_time);
            else if (!strcmp(k, "KeepaliveTimeout"))       parse_range(v, &cfg->keepalive_timeout);
            else if (!strcmp(k, "MaxHandshakeAttempts"))   parse_range(v, &cfg->max_handshake_attempts);
            else if (!strcmp(k, "ContentPaddingAddition")) parse_range(v, &cfg->content_padding_addition);
            else if (k[0] == 'I' && k[1] >= '1' && k[1] <= '5' && k[2] == 0) {
                int idx = k[1] - '1';
                cfg->i[idx] = awg_obf_parse(v, kerr, sizeof(kerr));
                if (!cfg->i[idx] && kerr[0]) goto bad;
            }
        } else {
            if (!strcmp(k, "PublicKey")) {
                if (parse_key(v, cfg->peer_public_key, kerr, sizeof(kerr), "PublicKey")) goto bad;
                cfg->have_peer_public_key = true;
            } else if (!strcmp(k, "PresharedKey")) {
                if (parse_key(v, cfg->preshared_key, kerr, sizeof(kerr), "PresharedKey")) goto bad;
                cfg->have_preshared_key = true;
            } else if (!strcmp(k, "Endpoint")) {
                /* Split on the last colon so IPv6 literals stay intact. */
                char *colon = strrchr(v, ':');
                if (!colon) { snprintf(kerr, sizeof(kerr), "Endpoint has no port"); goto bad; }
                *colon = 0;
                cfg->endpoint_port = atoi(colon + 1);
                snprintf(cfg->endpoint_host, sizeof(cfg->endpoint_host), "%s", v);
            } else if (!strcmp(k, "PersistentKeepalive")) {
                parse_range(v, &cfg->persistent_keepalive);
            }
            /* AllowedIPs is accepted and ignored: this client always sends
             * everything through the tunnel, and routing on the console is
             * decided by which sockets we intercept, not by the peer config. */
        }
        continue;

    bad:
        snprintf(err, errsz, "line %d (%s): %s", lineno, k, kerr);
        rc = -1;
        break;
    }

    free(line);
    fclose(f);

    if (rc == 0) {
        if (!cfg->have_private_key)    { snprintf(err, errsz, "no PrivateKey"); rc = -1; }
        else if (!cfg->have_peer_public_key) { snprintf(err, errsz, "no peer PublicKey"); rc = -1; }
        else if (!cfg->endpoint_host[0])     { snprintf(err, errsz, "no Endpoint"); rc = -1; }
    }
    if (rc != 0) awg_config_free(cfg);
    return rc;
}

/* ------------------------------------------------------------------ dump */

static void ip_str(uint32_t net_order, char *out, size_t n)
{
    const uint8_t *b = (const uint8_t *)&net_order;
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void range_str(const awg_range *r, char *out, size_t n)
{
    if (r->max > r->min) snprintf(out, n, "%d-%d", r->min, r->max);
    else                 snprintf(out, n, "%d", r->min);
}

void awg_config_dump(const awg_config *cfg, void *fp)
{
    FILE *f = (FILE *)fp;
    char buf[64], buf2[64];

    ip_str(cfg->address, buf, sizeof(buf));
    fprintf(f, "interface\n");
    fprintf(f, "  address        %s/%d\n", buf, cfg->address_cidr);
    for (int i = 0; i < cfg->dns_n; i++) {
        ip_str(cfg->dns[i], buf, sizeof(buf));
        fprintf(f, "  dns[%d]         %s\n", i, buf);
    }
    fprintf(f, "  private key    %s\n", cfg->have_private_key ? "loaded" : "MISSING");
    fprintf(f, "  junk packets   Jc=%d Jmin=%d Jmax=%d\n", cfg->jc, cfg->jmin, cfg->jmax);
    fprintf(f, "  header junk    S1=%d S2=%d S3=%d S4=%d\n", cfg->s1, cfg->s2, cfg->s3, cfg->s4);
    fprintf(f, "  msg types      H1=%u H2=%u H3=%u H4=%u\n", cfg->h1, cfg->h2, cfg->h3, cfg->h4);
    fprintf(f, "  header protect %s\n",
            cfg->have_header_protection ? "on (ChaCha20)" : "off");

    range_str(&cfg->rekey_after_time, buf, sizeof(buf));
    range_str(&cfg->rekey_timeout, buf2, sizeof(buf2));
    fprintf(f, "  rekey          after %ss, timeout %ss\n", buf, buf2);
    range_str(&cfg->reject_after_time, buf, sizeof(buf));
    range_str(&cfg->keepalive_timeout, buf2, sizeof(buf2));
    fprintf(f, "  reject after   %ss, keepalive timeout %ss\n", buf, buf2);
    range_str(&cfg->max_handshake_attempts, buf, sizeof(buf));
    range_str(&cfg->content_padding_addition, buf2, sizeof(buf2));
    fprintf(f, "  handshakes     max %s, content padding %s B\n", buf, buf2);

    for (int i = 0; i < AWG_MAX_I; i++) {
        if (!cfg->i[i]) continue;
        fprintf(f, "  I%d             %d tags, %d bytes on the wire\n",
                i + 1, cfg->i[i]->n, awg_obf_out_len(cfg->i[i], 0));
    }

    fprintf(f, "peer\n");
    fprintf(f, "  public key     %s\n", cfg->have_peer_public_key ? "loaded" : "MISSING");
    fprintf(f, "  preshared key  %s\n", cfg->have_preshared_key ? "loaded" : "none");
    fprintf(f, "  endpoint       %s:%d\n", cfg->endpoint_host, cfg->endpoint_port);
    range_str(&cfg->persistent_keepalive, buf, sizeof(buf));
    fprintf(f, "  keepalive      %ss\n", buf);
}
