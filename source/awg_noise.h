/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * WireGuard's Noise_IKpsk2 handshake, plus the AmneziaWG framing that wraps it.
 *
 * The responder half is implemented too. A client never needs it, but it lets
 * the whole handshake be verified offline by running both ends against each
 * other - which matters here, because the alternative is debugging against a
 * live server that answers a wrong packet with silence.
 */
#ifndef SYS_AWG_AWG_NOISE_H
#define SYS_AWG_AWG_NOISE_H

#include "awg.h"

#define AWG_MSG_INIT_SIZE 148
#define AWG_MSG_RESP_SIZE 92

/* Which of S1..S4 applies, and which of H1..H4 identifies the message. */
typedef enum {
    AWG_KIND_INIT     = 0,
    AWG_KIND_RESPONSE = 1,
    AWG_KIND_COOKIE   = 2,
    AWG_KIND_TRANSPORT = 3
} awg_kind;

typedef struct {
    uint8_t  ck[32];         /* chaining key   */
    uint8_t  h[32];          /* running hash   */

    uint8_t  s_priv[32];     /* our static     */
    uint8_t  s_pub[32];
    uint8_t  e_priv[32];     /* our ephemeral  */
    uint8_t  e_pub[32];

    uint8_t  peer_pub[32];   /* their static; learned by the responder */
    uint8_t  peer_eph[32];   /* their ephemeral */
    uint8_t  psk[32];

    uint32_t local_index;
    uint32_t remote_index;

    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    bool     established;
} awg_handshake;

/* Derives the public key for a private one (clamped, as WireGuard requires). */
void awg_public_from_private(uint8_t pub[32], const uint8_t priv[32]);

/* Generates a fresh clamped static private key. */
void awg_generate_private(uint8_t priv[32]);

/* `peer_pub` may be all zeroes on the responder, which learns it from the
 * initiation. `psk` may be NULL when no preshared key is configured. */
void awg_handshake_begin(awg_handshake *hs, const uint8_t s_priv[32],
                         const uint8_t peer_pub[32], const uint8_t psk[32],
                         uint32_t local_index);

/* Initiator. */
int awg_create_initiation(awg_handshake *hs, uint8_t out[AWG_MSG_INIT_SIZE]);
int awg_consume_response(awg_handshake *hs, const uint8_t in[AWG_MSG_RESP_SIZE]);

/* Responder - offline verification only. */
int awg_consume_initiation(awg_handshake *hs, const uint8_t in[AWG_MSG_INIT_SIZE]);
int awg_create_response(awg_handshake *hs, uint8_t out[AWG_MSG_RESP_SIZE]);

/* ------------------------------------------------------- AmneziaWG framing */

/*
 * Wraps a bare WireGuard message into what AmneziaWG puts on the wire:
 *
 *   [ S<kind> random bytes ][ message, XORed with ChaCha20 ]
 *
 * The random prefix doubles as the header-protection nonce (its first 12
 * bytes), which is why it can never be shorter than that. Returns the total
 * length, or -1 if the output buffer is too small or the padding too short.
 */
int awg_wrap(const awg_config *cfg, awg_kind kind,
             const uint8_t *msg, int msg_len, uint8_t *out, int out_cap);

/*
 * Reverses awg_wrap in place. `pkt` is the received datagram; on success
 * `*msg_off` gives where the plaintext message starts. Returns the message
 * length, or -1 if the datagram is too short for the expected padding.
 */
int awg_unwrap(const awg_config *cfg, awg_kind kind,
               uint8_t *pkt, int pkt_len, int *msg_off);

/* Junk datagrams to send ahead of an initiation. Fills up to `max_packets`
 * buffers of at most `cap` bytes each, returns how many were produced. */
int awg_junk_packets(const awg_config *cfg, uint8_t *bufs, int cap,
                     int *lens, int max_packets);

/* --------------------------------------------------------------- transport */

/*
 * A data packet looks like:
 *
 *   [ S4 random bytes ][ 16-byte header, ChaCha20-XORed ][ AEAD(payload) ]
 *
 * Only the header gets the obfuscation pass - the payload is already
 * encrypted. The header is type, receiver index and a 64-bit counter, and
 * that counter is also the AEAD nonce, so it must never repeat for a key.
 *
 * The payload is padded with zeroes to a multiple of 16. The peer ignores the
 * padding because an IPv4 header carries its own length.
 *
 * Returns the datagram length, or -1 if it would not fit.
 */
int awg_transport_seal(const awg_config *cfg, const awg_handshake *hs,
                       uint64_t counter, const uint8_t *payload, int payload_len,
                       uint8_t *out, int out_cap);

/*
 * Reverses the above. Returns the payload length (padding included, so the
 * caller must trust the inner header's own length field), or -1 when the
 * datagram is malformed, addressed to another session, or fails its tag.
 * `counter` receives the sender's counter for replay bookkeeping.
 */
int awg_transport_open(const awg_config *cfg, const awg_handshake *hs,
                       uint8_t *pkt, int pkt_len,
                       uint8_t *out, int out_cap, uint64_t *counter);

#endif /* SYS_AWG_AWG_NOISE_H */
