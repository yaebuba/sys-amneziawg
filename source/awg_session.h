/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Session lifetime: keeping a tunnel alive rather than just opening one.
 *
 * A WireGuard session is deliberately short-lived. Keys expire, and a peer
 * that never rekeys simply goes quiet after a couple of minutes - which is
 * exactly what stage 2 did. This layer owns the timers and the key rotation
 * so the caller only has to move bytes.
 *
 * All timings come from the config as ranges and are drawn per session, so
 * the tunnel has no fixed rhythm for a classifier to lock onto.
 *
 * No sockets here: the caller sends what we hand it and hands us what it
 * receives. That keeps this file portable and testable off-console.
 */
#ifndef SYS_AWG_SESSION_H
#define SYS_AWG_SESSION_H

#include "awg.h"
#include "awg_noise.h"

/* What the caller should do with a datagram we were given. */
typedef enum {
    AWG_RX_IGNORED = 0,   /* not ours, or malformed - drop it            */
    AWG_RX_HANDLED,       /* protocol traffic; nothing for the caller    */
    AWG_RX_PAYLOAD,       /* an inner IP packet was decrypted            */
    AWG_RX_ESTABLISHED    /* a handshake completed; the tunnel is up     */
} awg_rx_result;

typedef struct {
    awg_handshake cur;              /* the live keypair                      */
    bool          established;

    /*
     * The keypair we just replaced. Packets the peer sent moments before the
     * rekey are still encrypted with it, and dropping them costs a TCP
     * recovery that showed up as a thirty second stall after every rotation.
     */
    awg_handshake prev;
    bool          have_prev;

    awg_handshake pending;          /* a handshake we have sent and not yet
                                     * had answered                          */
    bool          handshaking;
    uint64_t      handshake_sent_ms;
    int           handshake_tries;

    uint64_t      tx_counter;       /* never repeats for a key - it is the
                                     * AEAD nonce                            */
    uint64_t      rx_counter_max;

    uint64_t      established_ms;
    uint64_t      last_tx_ms;
    uint64_t      last_rx_ms;

    /* Drawn once per session from the configured ranges. */
    int rekey_after_s;
    int reject_after_s;
    int keepalive_s;
    int rekey_timeout_s;
    int max_tries;

    /* Counters, for the log. */
    uint32_t handshakes_done;
    uint32_t rekeys;
    uint32_t packets_tx;
    uint32_t packets_rx;
    uint32_t keepalives_tx;
} awg_session;

void awg_session_init(awg_session *s, const awg_config *cfg);

/* True when a fresh handshake should be started: no session yet, the current
 * one is due for rotation, or an attempt has gone unanswered long enough. */
bool awg_session_needs_handshake(const awg_session *s, const awg_config *cfg,
                                 uint64_t now_ms);

/* True once the session has been idle for a keepalive period. WireGuard uses
 * these to hold the NAT mapping open; without them the peer cannot reach us. */
bool awg_session_needs_keepalive(const awg_session *s, uint64_t now_ms);

/* Builds a handshake initiation and arms the retry timer. */
int awg_session_build_initiation(awg_session *s, const awg_config *cfg,
                                 uint8_t *out, int out_cap, uint64_t now_ms);

/* Wraps an inner IP packet for sending. Returns the datagram length, or -1
 * if there is no live session or it would not fit. */
int awg_session_build_data(awg_session *s, const awg_config *cfg,
                           const uint8_t *payload, int payload_len,
                           uint8_t *out, int out_cap, uint64_t now_ms);

/* An empty data packet, which is what a WireGuard keepalive is. */
int awg_session_build_keepalive(awg_session *s, const awg_config *cfg,
                                uint8_t *out, int out_cap, uint64_t now_ms);

/*
 * Feeds a received datagram in. On AWG_RX_PAYLOAD, `payload` holds the inner
 * packet and `*payload_len` its length. `pkt` is modified in place.
 */
awg_rx_result awg_session_on_datagram(awg_session *s, const awg_config *cfg,
                                      uint8_t *pkt, int pkt_len,
                                      uint8_t *payload, int payload_cap,
                                      int *payload_len, uint64_t now_ms);

/* Seconds the current session has been up, or 0 when there is none. */
uint32_t awg_session_age_s(const awg_session *s, uint64_t now_ms);

#endif /* SYS_AWG_SESSION_H */
