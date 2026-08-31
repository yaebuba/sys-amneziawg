/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s, per the WireGuard paper,
 * plus AmneziaWG's framing on top.
 *
 * Crypto primitives come from smartalock/wireguard-lwip (BSD-3, (c) 2021
 * Daniel Hope); everything in this file is our own.
 */
#include <string.h>
#include <time.h>

#include "awg_noise.h"
#include "crypto/blake2s.h"
#include "crypto/chacha20.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/x25519.h"

/* Exactly as WireGuard spells it - the cipher is abbreviated, not written out
 * in full. This string seeds the chaining key, so a single character off makes
 * every derived key wrong and the server drops us without a word. Two peers
 * that share the mistake still agree with each other, which is why a loopback
 * test cannot catch it. */
static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[]   = "mac1----";

/* ------------------------------------------------------------ primitives */

static void hash2(uint8_t out[32], const uint8_t *a, size_t alen,
                  const uint8_t *b, size_t blen)
{
    blake2s_ctx c;
    blake2s_init(&c, 32, NULL, 0);
    if (a && alen) blake2s_update(&c, a, alen);
    if (b && blen) blake2s_update(&c, b, blen);
    blake2s_final(&c, out);
}

/* h = HASH(h || data) */
static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len)
{
    hash2(h, h, 32, data, len);
}

static void hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen,
                         const uint8_t *in, size_t inlen)
{
    uint8_t k[BLAKE2S_BLOCK_SIZE], ipad[BLAKE2S_BLOCK_SIZE], opad[BLAKE2S_BLOCK_SIZE];
    uint8_t inner[32];
    blake2s_ctx c;

    memset(k, 0, sizeof(k));
    if (keylen > BLAKE2S_BLOCK_SIZE) blake2s(k, 32, NULL, 0, key, keylen);
    else if (keylen)                 memcpy(k, key, keylen);

    for (int i = 0; i < BLAKE2S_BLOCK_SIZE; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, ipad, sizeof(ipad));
    if (in && inlen) blake2s_update(&c, in, inlen);
    blake2s_final(&c, inner);

    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, opad, sizeof(opad));
    blake2s_update(&c, inner, sizeof(inner));
    blake2s_final(&c, out);
}

/* HKDF as WireGuard uses it; t2/t3 may be NULL when fewer outputs are wanted. */
static void kdf(uint8_t *t1, uint8_t *t2, uint8_t *t3,
                const uint8_t ck[32], const uint8_t *data, size_t datalen)
{
    uint8_t t0[32], buf[33];

    hmac_blake2s(t0, ck, 32, data, datalen);

    buf[0] = 1;
    hmac_blake2s(t1, t0, 32, buf, 1);
    if (!t2) return;

    memcpy(buf, t1, 32); buf[32] = 2;
    hmac_blake2s(t2, t0, 32, buf, 33);
    if (!t3) return;

    memcpy(buf, t2, 32); buf[32] = 3;
    hmac_blake2s(t3, t0, 32, buf, 33);
}

static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* TAI64N, as WireGuard stamps its initiations. */
static void tai64n(uint8_t out[12])
{
    uint64_t secs = awg_now_seconds() + 0x400000000000000aULL;
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(secs & 0xFF); secs >>= 8; }
    /* Nanoseconds only need to be monotonic within a second; the server uses
     * the stamp for replay rejection, not for timekeeping. */
    uint32_t nanos = 0;
    awg_random_bytes(&nanos, sizeof(nanos));
    nanos %= 1000000000u;
    out[8]  = (uint8_t)(nanos >> 24); out[9]  = (uint8_t)(nanos >> 16);
    out[10] = (uint8_t)(nanos >> 8);  out[11] = (uint8_t)nanos;
}

/* mac1 is keyed on the *receiver's* static public key. */
static void mac1(uint8_t out[16], const uint8_t recv_pub[32],
                 const uint8_t *msg, size_t len)
{
    uint8_t key[32];
    blake2s_ctx c;

    blake2s_init(&c, 32, NULL, 0);
    blake2s_update(&c, LABEL_MAC1, sizeof(LABEL_MAC1) - 1);
    blake2s_update(&c, recv_pub, 32);
    blake2s_final(&c, key);

    blake2s(out, 16, key, 32, msg, len);
}

/* --------------------------------------------------------------- keys */

void awg_public_from_private(uint8_t pub[32], const uint8_t priv[32])
{
    x25519_base(pub, priv, 1);
}

void awg_generate_private(uint8_t priv[32])
{
    awg_random_bytes(priv, 32);
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

/* --------------------------------------------------------- handshake */

void awg_handshake_begin(awg_handshake *hs, const uint8_t s_priv[32],
                         const uint8_t peer_pub[32], const uint8_t psk[32],
                         uint32_t local_index)
{
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->s_priv, s_priv, 32);
    awg_public_from_private(hs->s_pub, s_priv);
    if (peer_pub) memcpy(hs->peer_pub, peer_pub, 32);
    if (psk)      memcpy(hs->psk, psk, 32);
    hs->local_index = local_index;
}

/* Both roles start from the same two constants. */
static void chain_start(awg_handshake *hs, const uint8_t responder_pub[32])
{
    hash2(hs->ck, (const uint8_t *)CONSTRUCTION, sizeof(CONSTRUCTION) - 1, NULL, 0);
    hash2(hs->h, hs->ck, 32, (const uint8_t *)IDENTIFIER, sizeof(IDENTIFIER) - 1);
    mix_hash(hs->h, responder_pub, 32);
}

int awg_create_initiation(awg_handshake *hs, uint8_t out[AWG_MSG_INIT_SIZE])
{
    uint8_t k[32], dh[32], stamp[12];

    chain_start(hs, hs->peer_pub);

    awg_generate_private(hs->e_priv);
    awg_public_from_private(hs->e_pub, hs->e_priv);

    memset(out, 0, AWG_MSG_INIT_SIZE);
    put_u32_le(out + 0, 1);                    /* type, with reserved bytes */
    put_u32_le(out + 4, hs->local_index);
    memcpy(out + 8, hs->e_pub, 32);

    kdf(hs->ck, NULL, NULL, hs->ck, hs->e_pub, 32);
    mix_hash(hs->h, hs->e_pub, 32);

    /* encrypted static */
    if (x25519(dh, hs->e_priv, hs->peer_pub, 1) != 0) return -1;
    kdf(hs->ck, k, NULL, hs->ck, dh, 32);
    chacha20poly1305_encrypt(out + 40, hs->s_pub, 32, hs->h, 32, 0, k);
    mix_hash(hs->h, out + 40, 48);

    /* encrypted timestamp */
    if (x25519(dh, hs->s_priv, hs->peer_pub, 1) != 0) return -1;
    kdf(hs->ck, k, NULL, hs->ck, dh, 32);
    tai64n(stamp);
    chacha20poly1305_encrypt(out + 88, stamp, 12, hs->h, 32, 0, k);
    mix_hash(hs->h, out + 88, 28);

    mac1(out + 116, hs->peer_pub, out, 116);
    /* mac2 stays zero: it is only required once the server issues a cookie,
     * which it does under load. Handled at a higher layer when that happens. */
    return AWG_MSG_INIT_SIZE;
}

int awg_consume_initiation(awg_handshake *hs, const uint8_t in[AWG_MSG_INIT_SIZE])
{
    uint8_t k[32], dh[32], stamp[12], expect[16];

    if (get_u32_le(in) != 1) return -1;

    chain_start(hs, hs->s_pub);

    mac1(expect, hs->s_pub, in, 116);
    if (memcmp(expect, in + 116, 16) != 0) return -1;

    hs->remote_index = get_u32_le(in + 4);
    memcpy(hs->peer_eph, in + 8, 32);

    kdf(hs->ck, NULL, NULL, hs->ck, hs->peer_eph, 32);
    mix_hash(hs->h, hs->peer_eph, 32);

    if (x25519(dh, hs->s_priv, hs->peer_eph, 1) != 0) return -1;
    kdf(hs->ck, k, NULL, hs->ck, dh, 32);
    if (!chacha20poly1305_decrypt(hs->peer_pub, in + 40, 48, hs->h, 32, 0, k))
        return -1;
    mix_hash(hs->h, in + 40, 48);

    if (x25519(dh, hs->s_priv, hs->peer_pub, 1) != 0) return -1;
    kdf(hs->ck, k, NULL, hs->ck, dh, 32);
    if (!chacha20poly1305_decrypt(stamp, in + 88, 28, hs->h, 32, 0, k))
        return -1;
    mix_hash(hs->h, in + 88, 28);

    return 0;
}

int awg_create_response(awg_handshake *hs, uint8_t out[AWG_MSG_RESP_SIZE])
{
    uint8_t k[32], t[32], dh[32];

    awg_generate_private(hs->e_priv);
    awg_public_from_private(hs->e_pub, hs->e_priv);

    memset(out, 0, AWG_MSG_RESP_SIZE);
    put_u32_le(out + 0, 2);
    put_u32_le(out + 4, hs->local_index);
    put_u32_le(out + 8, hs->remote_index);
    memcpy(out + 12, hs->e_pub, 32);

    kdf(hs->ck, NULL, NULL, hs->ck, hs->e_pub, 32);
    mix_hash(hs->h, hs->e_pub, 32);

    if (x25519(dh, hs->e_priv, hs->peer_eph, 1) != 0) return -1;
    kdf(hs->ck, NULL, NULL, hs->ck, dh, 32);

    if (x25519(dh, hs->e_priv, hs->peer_pub, 1) != 0) return -1;
    kdf(hs->ck, NULL, NULL, hs->ck, dh, 32);

    kdf(hs->ck, t, k, hs->ck, hs->psk, 32);
    mix_hash(hs->h, t, 32);

    chacha20poly1305_encrypt(out + 44, NULL, 0, hs->h, 32, 0, k);
    mix_hash(hs->h, out + 44, 16);

    mac1(out + 60, hs->peer_pub, out, 60);

    /* The responder receives on the first derived key and sends on the
     * second; the initiator does the opposite. */
    kdf(hs->recv_key, hs->send_key, NULL, hs->ck, NULL, 0);
    hs->established = true;
    return AWG_MSG_RESP_SIZE;
}

int awg_consume_response(awg_handshake *hs, const uint8_t in[AWG_MSG_RESP_SIZE])
{
    uint8_t k[32], t[32], dh[32], empty[1], expect[16];

    if (get_u32_le(in) != 2) return -1;
    if (get_u32_le(in + 8) != hs->local_index) return -1;

    mac1(expect, hs->s_pub, in, 60);
    if (memcmp(expect, in + 60, 16) != 0) return -1;

    hs->remote_index = get_u32_le(in + 4);
    memcpy(hs->peer_eph, in + 12, 32);

    kdf(hs->ck, NULL, NULL, hs->ck, hs->peer_eph, 32);
    mix_hash(hs->h, hs->peer_eph, 32);

    if (x25519(dh, hs->e_priv, hs->peer_eph, 1) != 0) return -1;
    kdf(hs->ck, NULL, NULL, hs->ck, dh, 32);

    if (x25519(dh, hs->s_priv, hs->peer_eph, 1) != 0) return -1;
    kdf(hs->ck, NULL, NULL, hs->ck, dh, 32);

    kdf(hs->ck, t, k, hs->ck, hs->psk, 32);
    mix_hash(hs->h, t, 32);

    if (!chacha20poly1305_decrypt(empty, in + 44, 16, hs->h, 32, 0, k))
        return -1;
    mix_hash(hs->h, in + 44, 16);

    kdf(hs->send_key, hs->recv_key, NULL, hs->ck, NULL, 0);
    hs->established = true;
    return 0;
}

/* ------------------------------------------------------------- framing */

static int padding_for(const awg_config *cfg, awg_kind kind)
{
    switch (kind) {
    case AWG_KIND_INIT:      return cfg->s1;
    case AWG_KIND_RESPONSE:  return cfg->s2;
    case AWG_KIND_COOKIE:    return cfg->s3;
    case AWG_KIND_TRANSPORT: return cfg->s4;
    }
    return 0;
}

/*
 * Header protection needs a full 96-bit nonce, but the bundled ChaCha20 only
 * exposes the 64-bit form WireGuard's transport uses. The state layout is
 * fixed by the cipher, so the remaining nonce word is written directly:
 * words 13..15 hold the 12 nonce bytes little-endian, word 12 the counter.
 */
static void header_cipher_init(struct chacha20_ctx *ctx,
                               const uint8_t key[32], const uint8_t nonce[12])
{
    chacha20_init(ctx, key, 0);
    ctx->state[12] = 0;
    for (int w = 0; w < 3; w++) {
        const uint8_t *p = nonce + 4 * w;
        ctx->state[13 + w] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                             ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }
}

int awg_wrap(const awg_config *cfg, awg_kind kind,
             const uint8_t *msg, int msg_len, uint8_t *out, int out_cap)
{
    int pad = padding_for(cfg, kind);

    /* The first 12 padding bytes are the nonce, so anything shorter cannot
     * carry header protection. */
    if (cfg->have_header_protection && pad < 12) return -1;
    if (pad < 0 || msg_len < 0 || pad + msg_len > out_cap) return -1;

    if (pad) awg_random_bytes(out, (size_t)pad);
    memcpy(out + pad, msg, (size_t)msg_len);

    if (cfg->have_header_protection) {
        struct chacha20_ctx ctx;
        header_cipher_init(&ctx, cfg->header_protection_key, out);
        chacha20(&ctx, out + pad, out + pad, (uint32_t)msg_len);
    }
    return pad + msg_len;
}

int awg_unwrap(const awg_config *cfg, awg_kind kind,
               uint8_t *pkt, int pkt_len, int *msg_off)
{
    int pad = padding_for(cfg, kind);

    if (cfg->have_header_protection && pad < 12) return -1;
    if (pkt_len <= pad) return -1;

    int msg_len = pkt_len - pad;

    if (cfg->have_header_protection) {
        struct chacha20_ctx ctx;
        header_cipher_init(&ctx, cfg->header_protection_key, pkt);
        chacha20(&ctx, pkt + pad, pkt + pad, (uint32_t)msg_len);
    }

    *msg_off = pad;
    return msg_len;
}

/* --------------------------------------------------------------- transport */

#define TRANSPORT_HDR 16
#define AEAD_TAG      16

static void put_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; }
}

static uint64_t get_u64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

int awg_transport_seal(const awg_config *cfg, const awg_handshake *hs,
                       uint64_t counter, const uint8_t *payload, int payload_len,
                       uint8_t *out, int out_cap)
{
    int pad = cfg->s4;
    if (cfg->have_header_protection && pad < 12) return -1;
    if (payload_len < 0) return -1;

    /* Pad the plaintext to a multiple of 16 so packet lengths reveal less
     * about the traffic inside. */
    int padded = (payload_len + 15) & ~15;
    int total  = pad + TRANSPORT_HDR + padded + AEAD_TAG;
    if (total > out_cap) return -1;

    if (pad) awg_random_bytes(out, (size_t)pad);

    uint8_t *hdr = out + pad;
    put_u32_le(hdr + 0, cfg->h4);
    put_u32_le(hdr + 4, hs->remote_index);
    put_u64_le(hdr + 8, counter);

    /* Seal in place: copy the payload past the header, zero the padding, then
     * encrypt over both. */
    uint8_t *body = hdr + TRANSPORT_HDR;
    if (payload_len) memcpy(body, payload, (size_t)payload_len);
    if (padded > payload_len) memset(body + payload_len, 0, (size_t)(padded - payload_len));

    chacha20poly1305_encrypt(body, body, (size_t)padded, NULL, 0, counter, hs->send_key);

    if (cfg->have_header_protection) {
        struct chacha20_ctx ctx;
        header_cipher_init(&ctx, cfg->header_protection_key, out);
        chacha20(&ctx, hdr, hdr, TRANSPORT_HDR);
    }
    return total;
}

int awg_transport_open(const awg_config *cfg, const awg_handshake *hs,
                       uint8_t *pkt, int pkt_len,
                       uint8_t *out, int out_cap, uint64_t *counter)
{
    int pad = cfg->s4;
    if (cfg->have_header_protection && pad < 12) return -1;
    if (pkt_len < pad + TRANSPORT_HDR + AEAD_TAG) return -1;

    uint8_t *hdr = pkt + pad;

    if (cfg->have_header_protection) {
        struct chacha20_ctx ctx;
        header_cipher_init(&ctx, cfg->header_protection_key, pkt);
        chacha20(&ctx, hdr, hdr, TRANSPORT_HDR);
    }

    /*
     * Restore the header before rejecting. The caller may try another key -
     * the previous keypair, during a rekey - and XOR is its own inverse, so
     * leaving the header decrypted would corrupt it for the second attempt.
     */
    #define REJECT() do {                                                     \
        if (cfg->have_header_protection) {                                    \
            struct chacha20_ctx rc;                                           \
            header_cipher_init(&rc, cfg->header_protection_key, pkt);         \
            chacha20(&rc, hdr, hdr, TRANSPORT_HDR);                           \
        }                                                                     \
        return -1;                                                            \
    } while (0)

    if (get_u32_le(hdr + 0) != cfg->h4) REJECT();
    if (get_u32_le(hdr + 4) != hs->local_index) REJECT();

    uint64_t ctr = get_u64_le(hdr + 8);

    int cipher_len = pkt_len - pad - TRANSPORT_HDR;
    int plain_len  = cipher_len - AEAD_TAG;
    if (plain_len < 0 || plain_len > out_cap) REJECT();

    if (!chacha20poly1305_decrypt(out, hdr + TRANSPORT_HDR, (size_t)cipher_len,
                                  NULL, 0, ctr, hs->recv_key))
        REJECT();

    #undef REJECT

    if (counter) *counter = ctr;
    return plain_len;
}

int awg_junk_packets(const awg_config *cfg, uint8_t *bufs, int cap,
                     int *lens, int max_packets)
{
    int n = cfg->jc;
    if (n > max_packets) n = max_packets;
    if (n <= 0) return 0;

    int span = cfg->jmax - cfg->jmin;

    for (int i = 0; i < n; i++) {
        uint32_t r = 0;
        if (span > 0) {
            awg_random_bytes(&r, sizeof(r));
            r %= (uint32_t)span;
        }
        int len = cfg->jmin + (int)r;
        if (len > cap) len = cap;
        if (len < 0) len = 0;

        awg_random_bytes(bufs + (size_t)i * (size_t)cap, (size_t)len);
        lens[i] = len;
    }
    return n;
}
