/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Session lifetime. See awg_session.h for the shape of this layer.
 */
#include <string.h>

#include "awg_session.h"

void awg_session_init(awg_session *s, const awg_config *cfg)
{
    memset(s, 0, sizeof(*s));

    /* Drawn once per session rather than per packet: the peer has to agree
     * about when keys expire, and re-rolling every time would make our own
     * behaviour inconsistent with what we told it. */
    s->rekey_after_s   = awg_range_pick(&cfg->rekey_after_time);
    s->reject_after_s  = awg_range_pick(&cfg->reject_after_time);
    s->rekey_timeout_s = awg_range_pick(&cfg->rekey_timeout);
    s->keepalive_s     = awg_range_pick(&cfg->persistent_keepalive);
    s->max_tries       = awg_range_pick(&cfg->max_handshake_attempts);

    if (s->rekey_after_s   <= 0) s->rekey_after_s   = 120;
    if (s->reject_after_s  <= 0) s->reject_after_s  = 180;
    if (s->rekey_timeout_s <= 0) s->rekey_timeout_s = 5;
    if (s->keepalive_s     <= 0) s->keepalive_s     = 25;
    if (s->max_tries       <= 0) s->max_tries       = 18;
}

bool awg_session_needs_handshake(const awg_session *s, const awg_config *cfg,
                                 uint64_t now_ms)
{
    (void)cfg;

    /* An attempt is outstanding: only retry once its timeout has run out. */
    if (s->handshaking)
        return (now_ms - s->handshake_sent_ms) >= (uint64_t)s->rekey_timeout_s * 1000;

    if (!s->established) return true;

    /* Rotate before the keys expire, not after - a session that has already
     * been rejected cannot carry the handshake that would replace it. */
    return (now_ms - s->established_ms) >= (uint64_t)s->rekey_after_s * 1000;
}

bool awg_session_needs_keepalive(const awg_session *s, uint64_t now_ms)
{
    if (!s->established) return false;
    return (now_ms - s->last_tx_ms) >= (uint64_t)s->keepalive_s * 1000;
}

int awg_session_build_initiation(awg_session *s, const awg_config *cfg,
                                 uint8_t *out, int out_cap, uint64_t now_ms)
{
    uint32_t idx;
    awg_random_bytes(&idx, sizeof(idx));

    awg_handshake_begin(&s->pending, cfg->private_key, cfg->peer_public_key,
                        cfg->have_preshared_key ? cfg->preshared_key : NULL, idx);

    uint8_t msg[AWG_MSG_INIT_SIZE];
    if (awg_create_initiation(&s->pending, msg) != AWG_MSG_INIT_SIZE) return -1;

    int n = awg_wrap(cfg, AWG_KIND_INIT, msg, AWG_MSG_INIT_SIZE, out, out_cap);
    if (n < 0) return -1;

    s->handshaking       = true;
    s->handshake_sent_ms = now_ms;
    s->handshake_tries++;
    return n;
}

int awg_session_build_data(awg_session *s, const awg_config *cfg,
                           const uint8_t *payload, int payload_len,
                           uint8_t *out, int out_cap, uint64_t now_ms)
{
    if (!s->established) return -1;

    int n = awg_transport_seal(cfg, &s->cur, s->tx_counter, payload, payload_len,
                               out, out_cap);
    if (n < 0) return -1;

    s->tx_counter++;
    s->packets_tx++;
    s->last_tx_ms = now_ms;
    return n;
}

int awg_session_build_keepalive(awg_session *s, const awg_config *cfg,
                                uint8_t *out, int out_cap, uint64_t now_ms)
{
    int n = awg_session_build_data(s, cfg, NULL, 0, out, out_cap, now_ms);
    if (n > 0) {
        s->keepalives_tx++;
        s->packets_tx--;      /* counted as a keepalive, not as traffic */
    }
    return n;
}

awg_rx_result awg_session_on_datagram(awg_session *s, const awg_config *cfg,
                                      uint8_t *pkt, int pkt_len,
                                      uint8_t *payload, int payload_cap,
                                      int *payload_len, uint64_t now_ms)
{
    if (payload_len) *payload_len = 0;

    /*
     * Datagrams are told apart by length, the same way the reference
     * implementation does it: each message type has its own padding, so the
     * totals do not collide.
     */
    if (s->handshaking && pkt_len == cfg->s2 + AWG_MSG_RESP_SIZE) {
        int off = 0;
        int mlen = awg_unwrap(cfg, AWG_KIND_RESPONSE, pkt, pkt_len, &off);
        if (mlen != AWG_MSG_RESP_SIZE) return AWG_RX_IGNORED;

        if (awg_consume_response(&s->pending, pkt + off) != 0)
            return AWG_RX_IGNORED;

        /* Promote the pending handshake. Counters restart because they are
         * the AEAD nonces for the new keys. */
        if (s->established) {
            s->rekeys++;
            s->prev      = s->cur;      /* keep it for late arrivals */
            s->have_prev = true;
        }
        s->cur            = s->pending;
        s->established    = true;
        s->handshaking    = false;
        s->handshake_tries = 0;
        s->tx_counter     = 0;
        s->rx_counter_max = 0;
        s->established_ms = now_ms;
        s->last_rx_ms     = now_ms;
        s->last_tx_ms     = now_ms;
        s->handshakes_done++;
        return AWG_RX_ESTABLISHED;
    }

    if (!s->established) return AWG_RX_IGNORED;

    uint64_t ctr = 0;
    int plain = awg_transport_open(cfg, &s->cur, pkt, pkt_len,
                                   payload, payload_cap, &ctr);

    /* Anything still in flight under the old keys is worth decrypting rather
     * than making TCP discover the loss the slow way. */
    if (plain < 0 && s->have_prev)
        plain = awg_transport_open(cfg, &s->prev, pkt, pkt_len,
                                   payload, payload_cap, &ctr);

    if (plain < 0) return AWG_RX_IGNORED;

    s->last_rx_ms = now_ms;
    if (ctr > s->rx_counter_max) s->rx_counter_max = ctr;

    /* An empty data packet is a keepalive: it proves the peer is alive and
     * refreshes our NAT mapping, but there is nothing to hand upwards. */
    if (plain == 0) return AWG_RX_HANDLED;

    s->packets_rx++;
    if (payload_len) *payload_len = plain;
    return AWG_RX_PAYLOAD;
}

uint32_t awg_session_age_s(const awg_session *s, uint64_t now_ms)
{
    if (!s->established) return 0;
    return (uint32_t)((now_ms - s->established_ms) / 1000);
}
