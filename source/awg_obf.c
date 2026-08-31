/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * AmneziaWG obfuscation templates.
 *
 * Ported from amneziawg-go device/obf*.go. The semantics that matter and are
 * easy to get wrong: every tag in a chain is handed the *whole* payload and
 * decides for itself how many bytes it contributes, so the payload-carrying
 * tags (d/ds/dz) are the only ones whose width depends on the payload. The
 * rest are fixed width and act as filler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "awg.h"

static const char CHARS52[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DIGITS10[] = "0123456789";

/* ---------------------------------------------------------------- base64 */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int awg_b64_encode_raw(const uint8_t *in, int n, char *out, int out_cap)
{
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        int rem = n - i;
        uint32_t v = (uint32_t)in[i] << 16;
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];

        int units = rem >= 3 ? 4 : rem + 1;   /* raw encoding: no padding */
        if (o + units > out_cap) return -1;
        for (int k = 0; k < units; k++)
            out[o++] = B64[(v >> (18 - 6 * k)) & 0x3F];
    }
    return o;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int awg_b64_decode(const char *in, uint8_t *out, int out_cap)
{
    uint32_t acc = 0;
    int bits = 0, o = 0;

    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r' || *p == ' ') continue;
        int v = b64_val(*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

/* ------------------------------------------------------------------ hex */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ----------------------------------------------------------------- parse */

static void chain_free_items(awg_obf_chain *c)
{
    if (!c) return;
    for (int i = 0; i < c->n; i++) free(c->items[i].data);
    free(c->items);
    free(c->spec);
}

void awg_obf_free(awg_obf_chain *c)
{
    if (!c) return;
    chain_free_items(c);
    free(c);
}

/* Builds one tag from its key and (optional) argument. */
static int build_tag(awg_obf *o, const char *key, const char *val,
                     char *err, size_t errsz)
{
    memset(o, 0, sizeof(*o));

    if (!strcmp(key, "b")) {
        if (!val || !*val) { snprintf(err, errsz, "<b> without bytes"); return -1; }
        if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) val += 2;
        size_t sl = strlen(val);
        if (sl == 0 || sl % 2) { snprintf(err, errsz, "<b> odd hex length"); return -1; }

        o->kind     = AWG_OBF_BYTES;
        o->data_len = (int)(sl / 2);
        o->data     = malloc((size_t)o->data_len);
        if (!o->data) { snprintf(err, errsz, "out of memory"); return -1; }
        for (int i = 0; i < o->data_len; i++) {
            int hi = hex_val(val[2 * i]), lo = hex_val(val[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                free(o->data); o->data = NULL;
                snprintf(err, errsz, "<b> bad hex digit");
                return -1;
            }
            o->data[i] = (uint8_t)((hi << 4) | lo);
        }
        return 0;
    }

    if (!strcmp(key, "t")) { o->kind = AWG_OBF_TIMESTAMP; return 0; }
    if (!strcmp(key, "d")) { o->kind = AWG_OBF_DATA;      return 0; }
    if (!strcmp(key, "ds")) { o->kind = AWG_OBF_DATASTRING; return 0; }

    /* Everything left takes a byte count. */
    awg_obf_kind k;
    if      (!strcmp(key, "r"))  k = AWG_OBF_RAND;
    else if (!strcmp(key, "rc")) k = AWG_OBF_RANDCHARS;
    else if (!strcmp(key, "rd")) k = AWG_OBF_RANDDIGITS;
    else if (!strcmp(key, "dz")) k = AWG_OBF_DATASIZE;
    else { snprintf(err, errsz, "unknown tag <%s>", key); return -1; }

    if (!val || !*val) { snprintf(err, errsz, "<%s> without a length", key); return -1; }
    char *end = NULL;
    long n = strtol(val, &end, 10);
    if (end == val || *end || n < 0 || n > (1 << 20)) {
        snprintf(err, errsz, "<%s> bad length '%s'", key, val);
        return -1;
    }
    o->kind = k;
    o->len  = (int)n;
    return 0;
}

awg_obf_chain *awg_obf_parse(const char *spec, char *err, size_t errsz)
{
    if (err && errsz) err[0] = 0;
    if (!spec || !*spec) return NULL;

    awg_obf_chain *c = calloc(1, sizeof(*c));
    if (!c) { if (err) snprintf(err, errsz, "out of memory"); return NULL; }

    int cap = 8;
    c->items = calloc((size_t)cap, sizeof(awg_obf));
    if (!c->items) { free(c); if (err) snprintf(err, errsz, "out of memory"); return NULL; }

    const char *p = spec;
    for (;;) {
        const char *lt = strchr(p, '<');
        if (!lt) break;
        const char *gt = strchr(lt, '>');
        if (!gt) {
            if (err) snprintf(err, errsz, "missing closing '>'");
            awg_obf_free(c);
            return NULL;
        }

        /* Split the tag body into key and optional argument. A <b> literal
         * runs to over a kilobyte of hex, so this cannot be a fixed buffer. */
        size_t tl = (size_t)(gt - lt - 1);
        char *tag = malloc(tl + 1);
        if (!tag) {
            if (err) snprintf(err, errsz, "out of memory");
            awg_obf_free(c);
            return NULL;
        }
        memcpy(tag, lt + 1, tl);
        tag[tl] = 0;

        char *key = tag;
        while (*key == ' ') key++;
        char *val = key;
        while (*val && *val != ' ') val++;
        if (*val) { *val++ = 0; while (*val == ' ') val++; }

        if (c->n == cap) {
            cap *= 2;
            awg_obf *grown = realloc(c->items, (size_t)cap * sizeof(awg_obf));
            if (!grown) {
                if (err) snprintf(err, errsz, "out of memory");
                free(tag);
                awg_obf_free(c);
                return NULL;
            }
            c->items = grown;
        }

        char terr[128] = {0};
        int trc = build_tag(&c->items[c->n], key, val, terr, sizeof(terr));
        free(tag);
        if (trc != 0) {
            if (err) snprintf(err, errsz, "%s", terr);
            awg_obf_free(c);
            return NULL;
        }
        c->n++;
        p = gt + 1;
    }

    if (c->n == 0) { awg_obf_free(c); return NULL; }

    size_t sl = strlen(spec);
    c->spec = malloc(sl + 1);
    if (c->spec) memcpy(c->spec, spec, sl + 1);
    return c;
}

/* ---------------------------------------------------------------- render */

static int tag_out_len(const awg_obf *o, int src_len)
{
    switch (o->kind) {
    case AWG_OBF_BYTES:      return o->data_len;
    case AWG_OBF_RAND:
    case AWG_OBF_RANDCHARS:
    case AWG_OBF_RANDDIGITS: return o->len;
    case AWG_OBF_TIMESTAMP:  return 4;
    case AWG_OBF_DATA:       return src_len;
    case AWG_OBF_DATASIZE:   return o->len;
    case AWG_OBF_DATASTRING: return (src_len / 3) * 4 + ((src_len % 3) ? src_len % 3 + 1 : 0);
    }
    return 0;
}

int awg_obf_out_len(const awg_obf_chain *c, int src_len)
{
    if (!c) return 0;
    int total = 0;
    for (int i = 0; i < c->n; i++) total += tag_out_len(&c->items[i], src_len);
    return total;
}

static void fill_random_from(uint8_t *dst, int n, const char *alphabet, int mod)
{
    awg_random_bytes(dst, (size_t)n);
    for (int i = 0; i < n; i++) dst[i] = (uint8_t)alphabet[dst[i] % mod];
}

void awg_obf_render(const awg_obf_chain *c, uint8_t *dst,
                    const uint8_t *src, int src_len)
{
    if (!c) return;

    int w = 0;
    for (int i = 0; i < c->n; i++) {
        const awg_obf *o = &c->items[i];
        int n = tag_out_len(o, src_len);

        switch (o->kind) {
        case AWG_OBF_BYTES:
            memcpy(dst + w, o->data, (size_t)o->data_len);
            break;
        case AWG_OBF_RAND:
            awg_random_bytes(dst + w, (size_t)o->len);
            break;
        case AWG_OBF_RANDCHARS:
            fill_random_from(dst + w, o->len, CHARS52, 52);
            break;
        case AWG_OBF_RANDDIGITS:
            fill_random_from(dst + w, o->len, DIGITS10, 10);
            break;
        case AWG_OBF_TIMESTAMP: {
            uint32_t t = (uint32_t)time(NULL);
            dst[w + 0] = (uint8_t)(t >> 24); dst[w + 1] = (uint8_t)(t >> 16);
            dst[w + 2] = (uint8_t)(t >> 8);  dst[w + 3] = (uint8_t)t;
            break;
        }
        case AWG_OBF_DATA:
            if (src && src_len > 0) memcpy(dst + w, src, (size_t)src_len);
            break;
        case AWG_OBF_DATASTRING:
            if (src && src_len > 0)
                awg_b64_encode_raw(src, src_len, (char *)(dst + w), n);
            break;
        case AWG_OBF_DATASIZE: {
            /* Big-endian, truncated to the declared width. */
            uint32_t v = (uint32_t)src_len;
            for (int k = o->len - 1; k >= 0; k--) { dst[w + k] = (uint8_t)(v & 0xFF); v >>= 8; }
            break;
        }
        }
        w += n;
    }
}

/* ----------------------------------------------------------------- range */

int awg_range_pick(const awg_range *r)
{
    if (r->max <= r->min) return r->min;
    uint32_t v;
    awg_random_bytes(&v, sizeof(v));
    return r->min + (int)(v % (uint32_t)(r->max - r->min + 1));
}
