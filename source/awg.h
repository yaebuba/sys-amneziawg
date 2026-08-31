/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * sys-amneziawg : AmneziaWG client core.
 *
 * Portable C, no platform headers here. The same translation units build for
 * the host (to debug against the real server at full speed) and for Horizon,
 * following the split sys-dpi used between main_linux.c and main_switch.c.
 *
 * Target is AmneziaWG 3.1, because that is what the server we have to talk to
 * speaks. Over plain WireGuard it adds: junk packets before the handshake,
 * per-message-type header values, a ChaCha20 header-protection layer, and
 * templated obfuscation packets (I1..I5).
 */
#ifndef SYS_AWG_AWG_H
#define SYS_AWG_AWG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define AWG_KEY_LEN   32
#define AWG_MAX_I     5     /* I1..I5 */

/* ------------------------------------------------------------ obfuscation */

/*
 * Amnezia describes an obfuscation packet as a chain of tags, e.g.
 *   <b 0xc700..><r 640><b 0xe78a..><r 64>
 * Each tag contributes a run of bytes to the output. Tags either emit fixed
 * or random filler (b, r, rc, rd, t) or carry the payload (d, ds, dz).
 */
typedef enum {
    AWG_OBF_BYTES,       /* <b 0xHEX>  literal bytes                        */
    AWG_OBF_RAND,        /* <r N>      N random bytes                       */
    AWG_OBF_RANDCHARS,   /* <rc N>     N random ASCII letters               */
    AWG_OBF_RANDDIGITS,  /* <rd N>     N random ASCII digits                */
    AWG_OBF_TIMESTAMP,   /* <t>        4-byte big-endian unix time          */
    AWG_OBF_DATA,        /* <d>        the payload, verbatim                */
    AWG_OBF_DATASTRING,  /* <ds>       the payload, base64 without padding  */
    AWG_OBF_DATASIZE     /* <dz N>     payload length, N bytes big-endian   */
} awg_obf_kind;

typedef struct {
    awg_obf_kind kind;
    int          len;        /* r / rc / rd / dz: the count from the tag */
    uint8_t     *data;       /* b: the literal bytes */
    int          data_len;
} awg_obf;

typedef struct {
    awg_obf *items;
    int      n;
    char    *spec;           /* the original template, kept for logging */
} awg_obf_chain;

/* Returns NULL on a malformed template. `err` (optional, size >= 128) gets a
 * short reason. An empty template yields NULL with err[0] == 0. */
awg_obf_chain *awg_obf_parse(const char *spec, char *err, size_t errsz);
void           awg_obf_free(awg_obf_chain *c);

/* Bytes the chain emits for a payload of `src_len`. */
int  awg_obf_out_len(const awg_obf_chain *c, int src_len);

/* Renders the chain into `dst`, which must hold awg_obf_out_len(c, src_len).
 * `src` may be NULL when the template carries no payload tag. */
void awg_obf_render(const awg_obf_chain *c, uint8_t *dst,
                    const uint8_t *src, int src_len);

/* ----------------------------------------------------------------- config */

/* Several AmneziaWG timings are ranges; a value is drawn per use so that the
 * traffic has no fixed rhythm for a classifier to lock onto. */
typedef struct { int min, max; } awg_range;

typedef struct {
    /* [Interface] */
    uint8_t  private_key[AWG_KEY_LEN];
    bool     have_private_key;
    uint32_t address;              /* our tunnel IPv4, network order */
    int      address_cidr;
    uint32_t dns[4];
    int      dns_n;

    /* Junk packets sent ahead of the handshake. */
    int      jc, jmin, jmax;

    /* Junk prepended inside each message type (init/response/cookie/data). */
    int      s1, s2, s3, s4;

    /* Replacements for WireGuard's four fixed message-type words. */
    uint32_t h1, h2, h3, h4;

    /* 3.1: ChaCha20 header protection. Nonce is the first 12 bytes of the
     * ciphertext, so only the key travels in the config. */
    uint8_t  header_protection_key[AWG_KEY_LEN];
    bool     have_header_protection;

    /* Randomised timings, all in seconds unless noted. */
    awg_range rekey_after_time;
    awg_range rekey_timeout;
    awg_range reject_after_time;
    awg_range keepalive_timeout;
    awg_range max_handshake_attempts;
    awg_range content_padding_addition;   /* bytes */

    /* I1..I5 obfuscation packets, NULL where unset. */
    awg_obf_chain *i[AWG_MAX_I];

    /* [Peer] */
    uint8_t  peer_public_key[AWG_KEY_LEN];
    bool     have_peer_public_key;
    uint8_t  preshared_key[AWG_KEY_LEN];
    bool     have_preshared_key;
    char     endpoint_host[128];
    int      endpoint_port;
    awg_range persistent_keepalive;
} awg_config;

/* Parses an AmneziaWG .conf. Returns 0 on success; on failure `err` explains
 * which line was rejected. */
int  awg_config_load(awg_config *cfg, const char *path, char *err, size_t errsz);
void awg_config_free(awg_config *cfg);

/* Human-readable dump, for the host harness. */
void awg_config_dump(const awg_config *cfg, void *fp);

/* ------------------------------------------------------------------ misc */

/* Platform-provided entropy: arc4random on the host, randomGet on Horizon. */
void awg_random_bytes(void *dst, size_t n);

/*
 * Seconds since the unix epoch, asked of the platform directly rather than
 * through time(). On Horizon newlib's clock reads as 1970 until the time
 * service is up, and a handshake stamped 1970 is rejected by the server as a
 * stale replay - silently, which is close to undebuggable.
 */
uint64_t awg_now_seconds(void);

/* Draws from an inclusive range. A degenerate range returns its single value. */
int  awg_range_pick(const awg_range *r);

/* base64 helpers. decode returns bytes written, or -1. */
int  awg_b64_decode(const char *in, uint8_t *out, int out_cap);
int  awg_b64_encode_raw(const uint8_t *in, int n, char *out, int out_cap);

#endif /* SYS_AWG_AWG_H */
