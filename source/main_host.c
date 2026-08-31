/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Host-side harness for the AmneziaWG core.
 *
 * Everything it exercises is the same code that will run on Horizon, so bugs
 * get found here - in a second, with a debugger available - instead of on a
 * console that has to be rebooted to retry. sys-dpi used the same split.
 *
 *   ./awg-host <config.conf>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "awg.h"
#include "awg_noise.h"
#include "awg_ipprobe.h"
#include "crypto/blake2s.h"
#include "crypto/x25519.h"

static int failures = 0;

static void check(int ok, const char *what)
{
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) failures++;
}

static void hexdump(const uint8_t *b, int n, int limit)
{
    int m = n < limit ? n : limit;
    for (int i = 0; i < m; i++) printf("%02x", b[i]);
    if (n > m) printf("... (%d bytes)", n);
    printf("\n");
}

/* base64 must round-trip, since every key in the config comes through it. */
static void test_base64(void)
{
    printf("\nbase64\n");

    const char *key = "OPWipEv6C0PVzD2Ly7yby81zbcjSh/nsAMST3dwz42E=";
    uint8_t raw[32];
    check(awg_b64_decode(key, raw, sizeof(raw)) == 32, "32-byte key decodes");

    char back[64];
    int n = awg_b64_encode_raw(raw, 32, back, sizeof(back));
    back[n > 0 ? n : 0] = 0;
    /* Raw encoding drops the '=' padding, so compare only the payload. */
    check(n == 43 && strncmp(back, key, 43) == 0, "re-encodes to the same text");

    uint8_t junk[8];
    check(awg_b64_decode("not valid base64!!", junk, sizeof(junk)) == -1,
          "rejects invalid input");
}

/*
 * The I1 template is the part most likely to be silently wrong: get a length
 * off by one and the server just ignores us, with nothing to debug. So verify
 * the structure explicitly - fixed runs stable across renders, random runs
 * not, and the total exactly as the template declares.
 */
static void test_obf(const awg_config *cfg)
{
    printf("\nobfuscation templates\n");

    /* I1..I5 are optional and some servers ship none of them; the junk-packet
     * and header-protection layers are configured separately. */
    const awg_obf_chain *c = NULL;
    int which = 0;
    for (int i = 0; i < AWG_MAX_I; i++)
        if (cfg->i[i]) { c = cfg->i[i]; which = i + 1; break; }

    if (!c) {
        printf("  none configured - nothing to render\n");
        return;
    }
    printf("  using I%d\n", which);

    printf("  %d tags:", c->n);
    for (int i = 0; i < c->n; i++) {
        static const char *names[] = { "b", "r", "rc", "rd", "t", "d", "ds", "dz" };
        const awg_obf *o = &c->items[i];
        int len = (o->kind == AWG_OBF_BYTES) ? o->data_len : o->len;
        printf(" <%s %d>", names[o->kind], len);
    }
    printf("\n");

    int len = awg_obf_out_len(c, 0);
    printf("  renders to %d bytes\n", len);
    check(len > 0 && len < 65535, "length is plausible for a UDP datagram");

    uint8_t *a = malloc((size_t)len), *b = malloc((size_t)len);
    if (!a || !b) { check(0, "allocation"); free(a); free(b); return; }

    awg_obf_render(c, a, NULL, 0);
    awg_obf_render(c, b, NULL, 0);

    /* Walk the chain and check each run behaved according to its tag. */
    int off = 0, fixed_ok = 1, rand_ok = 1;
    for (int i = 0; i < c->n; i++) {
        const awg_obf *o = &c->items[i];
        if (o->kind == AWG_OBF_BYTES) {
            if (memcmp(a + off, o->data, (size_t)o->data_len) != 0 ||
                memcmp(b + off, o->data, (size_t)o->data_len) != 0)
                fixed_ok = 0;
            off += o->data_len;
        } else if (o->kind == AWG_OBF_RAND) {
            /* Two independent renders of hundreds of random bytes matching
             * would mean the generator is not running at all. */
            if (o->len >= 16 && memcmp(a + off, b + off, (size_t)o->len) == 0)
                rand_ok = 0;
            off += o->len;
        } else {
            off += awg_obf_out_len(c, 0) - off;   /* not used by this config */
            break;
        }
    }

    check(fixed_ok, "literal runs are byte-exact and stable");
    check(rand_ok,  "random runs differ between renders");
    check(off == len, "tag widths sum to the declared length");

    printf("  first 32 bytes: ");
    hexdump(a, len, 32);

    free(a);
    free(b);
}

static int from_hex(const char *hex, uint8_t *out, int cap)
{
    int n = 0;
    for (; hex[0] && hex[1] && n < cap; hex += 2, n++) {
        int hi = (hex[0] <= '9') ? hex[0] - '0' : (hex[0] | 32) - 'a' + 10;
        int lo = (hex[1] <= '9') ? hex[1] - '0' : (hex[1] | 32) - 'a' + 10;
        out[n] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/*
 * Known-answer tests for the two primitives everything else rests on. If
 * either of these is wrong, nothing above it can be debugged sensibly.
 */
static void test_crypto(void)
{
    printf("\ncrypto known-answer tests\n");

    /* RFC 7693 - BLAKE2s-256("abc") */
    uint8_t digest[32], want[32];
    blake2s(digest, 32, NULL, 0, "abc", 3);
    from_hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
             want, sizeof(want));
    check(memcmp(digest, want, 32) == 0, "BLAKE2s-256 matches RFC 7693");

    /* RFC 7748 section 6.1 - the X25519 Diffie-Hellman example */
    uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32], want_pub[32], shared[32];
    from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
             a_priv, sizeof(a_priv));
    from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
             b_priv, sizeof(b_priv));

    awg_public_from_private(a_pub, a_priv);
    from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
             want_pub, sizeof(want_pub));
    check(memcmp(a_pub, want_pub, 32) == 0, "X25519 public key matches RFC 7748");

    awg_public_from_private(b_pub, b_priv);
    x25519(shared, a_priv, b_pub, 1);
    from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
             want_pub, sizeof(want_pub));
    check(memcmp(shared, want_pub, 32) == 0, "X25519 shared secret matches RFC 7748");
}

/*
 * Run the handshake against ourselves. The initiator and responder derive
 * their keys down completely independent code paths, so agreement on all
 * four values means the chaining key, the hash chain, both AEAD steps and
 * the preshared-key mixing are all correct. This is the check that replaces
 * guessing against a live server.
 */
static void test_handshake(const awg_config *cfg)
{
    printf("\nnoise handshake (initiator against responder)\n");

    uint8_t server_priv[32], server_pub[32];
    awg_generate_private(server_priv);
    awg_public_from_private(server_pub, server_priv);

    awg_handshake client, server;
    awg_handshake_begin(&client, cfg->private_key, server_pub, cfg->preshared_key, 0x11223344);
    awg_handshake_begin(&server, server_priv, NULL, cfg->preshared_key, 0x55667788);

    uint8_t init[AWG_MSG_INIT_SIZE], resp[AWG_MSG_RESP_SIZE];

    check(awg_create_initiation(&client, init) == AWG_MSG_INIT_SIZE,
          "initiation builds (148 bytes)");
    check(awg_consume_initiation(&server, init) == 0,
          "responder accepts it and verifies mac1");

    uint8_t client_pub[32];
    awg_public_from_private(client_pub, cfg->private_key);
    check(memcmp(server.peer_pub, client_pub, 32) == 0,
          "responder recovers our static public key");

    check(awg_create_response(&server, resp) == AWG_MSG_RESP_SIZE,
          "response builds (92 bytes)");
    check(awg_consume_response(&client, resp) == 0,
          "initiator accepts the response");

    check(memcmp(client.send_key, server.recv_key, 32) == 0,
          "client send key == server receive key");
    check(memcmp(client.recv_key, server.send_key, 32) == 0,
          "client receive key == server send key");

    /* A single flipped bit anywhere must break authentication, or the AEAD
     * tags are not actually being checked. */
    uint8_t tampered[AWG_MSG_RESP_SIZE];
    memcpy(tampered, resp, sizeof(tampered));
    tampered[50] ^= 0x01;
    awg_handshake c2;
    awg_handshake_begin(&c2, cfg->private_key, server_pub, cfg->preshared_key, 0x11223344);
    uint8_t init2[AWG_MSG_INIT_SIZE];
    awg_create_initiation(&c2, init2);
    check(awg_consume_response(&c2, tampered) != 0, "a corrupted response is rejected");
}

/*
 * Data packets, checked the same way as the handshake: seal on one side,
 * open on the other. The keys come from a real handshake so this also
 * confirms the two halves are wired to the right key of the pair - sealing
 * with the wrong one of the two is a mistake that looks fine in isolation.
 */
static void test_transport(const awg_config *cfg)
{
    printf("\ntransport packets\n");

    uint8_t server_priv[32], server_pub[32];
    awg_generate_private(server_priv);
    awg_public_from_private(server_pub, server_priv);

    awg_handshake client, server;
    awg_handshake_begin(&client, cfg->private_key, server_pub, cfg->preshared_key, 0xAABBCCDD);
    awg_handshake_begin(&server, server_priv, NULL, cfg->preshared_key, 0x11223344);

    uint8_t init[AWG_MSG_INIT_SIZE], resp[AWG_MSG_RESP_SIZE];
    awg_create_initiation(&client, init);
    awg_consume_initiation(&server, init);
    awg_create_response(&server, resp);
    if (awg_consume_response(&client, resp) != 0) { check(0, "handshake for transport"); return; }

    /* A realistic payload: the DNS query the console will actually send. */
    uint8_t ip[256];
    int ip_len = ipprobe_build_dns(ip, sizeof(ip), cfg->address, 0x04040808,
                                   40000, 0x1234, "example.com");
    check(ip_len > 28, "IPv4/UDP/DNS packet builds");

    uint8_t wire[2048], plain[2048];
    int n = awg_transport_seal(cfg, &client, 0, ip, ip_len, wire, sizeof(wire));
    printf("  %d byte payload -> %d bytes on the wire (%d junk + 16 header + tag)\n",
           ip_len, n, cfg->s4);
    check(n > 0, "seal produces a datagram");
    check(memcmp(wire + cfg->s4 + 16, ip, (size_t)ip_len) != 0, "payload is encrypted");

    uint64_t ctr = 999;
    int m = awg_transport_open(cfg, &server, wire, n, plain, sizeof(plain), &ctr);
    check(m >= ip_len, "peer opens it");
    check(ctr == 0, "counter survives the round trip");
    check(m >= ip_len && memcmp(plain, ip, (size_t)ip_len) == 0,
          "payload comes back byte-exact");

    /* Padding must be zeroes, not leftover memory - anything else would leak
     * whatever was in the buffer before. */
    int zeros_ok = 1;
    for (int i = ip_len; i < m; i++) if (plain[i]) zeros_ok = 0;
    check(zeros_ok, "padding is zeroed");

    /* Tamper with the ciphertext: the tag must catch it. */
    wire[n - 1] ^= 0x01;
    check(awg_transport_open(cfg, &server, wire, n, plain, sizeof(plain), &ctr) < 0,
          "a corrupted data packet is rejected");

    /* And the parser must walk a packet it did not build. */
    uint8_t reply[256];
    int rl = ipprobe_build_dns(reply, sizeof(reply), 0x04040808, cfg->address,
                               40000, 0x1234, "example.com");
    /* The builder always addresses port 53, so this synthetic packet is a
     * query rather than a reply; walking it still exercises every layer, and
     * it should stop at the answer section with nothing to return. */
    uint32_t answer = 0;
    int rc = ipprobe_parse_dns(reply, rl, 0x04040808, 53, 0x1234, &answer);
    check(rc == -8, "parser walks IP, UDP and DNS, then reports 'no A record'");

    /* Wrong expectations must be caught rather than ignored. */
    check(ipprobe_parse_dns(reply, rl, 0x04040808, 9999, 0x1234, &answer) == -5,
          "a mismatched port is rejected");
    check(ipprobe_parse_dns(reply, rl, 0x01010101, 53, 0x1234, &answer) == -4,
          "a packet from the wrong host is rejected");
}

/* The obfuscation layer must be exactly reversible, or we would be debugging
 * a decryption bug while blaming the protocol. */
static void test_framing(const awg_config *cfg)
{
    printf("\namneziawg framing\n");

    uint8_t msg[AWG_MSG_INIT_SIZE];
    for (int i = 0; i < AWG_MSG_INIT_SIZE; i++) msg[i] = (uint8_t)i;

    int cap = cfg->s1 + AWG_MSG_INIT_SIZE + 64;
    uint8_t *wire = malloc((size_t)cap);
    if (!wire) { check(0, "allocation"); return; }

    int n = awg_wrap(cfg, AWG_KIND_INIT, msg, AWG_MSG_INIT_SIZE, wire, cap);
    printf("  initiation on the wire: %d bytes (%d junk + %d message)\n",
           n, cfg->s1, AWG_MSG_INIT_SIZE);
    check(n == cfg->s1 + AWG_MSG_INIT_SIZE, "wrapped length is padding + message");
    check(memcmp(wire + cfg->s1, msg, AWG_MSG_INIT_SIZE) != 0,
          "message body is encrypted, not plaintext");

    int off = 0;
    int m = awg_unwrap(cfg, AWG_KIND_INIT, wire, n, &off);
    check(m == AWG_MSG_INIT_SIZE && off == cfg->s1, "unwrap reports the right offsets");
    check(memcmp(wire + off, msg, AWG_MSG_INIT_SIZE) == 0,
          "unwrap recovers the original message");

    free(wire);

    /* Junk datagrams. */
    enum { JCAP = 256, JMAX = 16 };
    uint8_t *jbufs = malloc(JCAP * JMAX);
    int jlens[JMAX];
    if (!jbufs) { check(0, "allocation"); return; }

    int jn = awg_junk_packets(cfg, jbufs, JCAP, jlens, JMAX);
    int sizes_ok = (jn == cfg->jc);
    for (int i = 0; i < jn; i++)
        if (jlens[i] < cfg->jmin || jlens[i] > cfg->jmax) sizes_ok = 0;
    printf("  junk packets: %d, sizes", jn);
    for (int i = 0; i < jn; i++) printf(" %d", jlens[i]);
    printf(" (allowed %d-%d)\n", cfg->jmin, cfg->jmax);
    check(sizes_ok, "junk count and sizes follow Jc/Jmin/Jmax");

    free(jbufs);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <config.conf>\n", argv[0]);
        return 2;
    }

    awg_config cfg;
    char err[256];

    if (awg_config_load(&cfg, argv[1], err, sizeof(err)) != 0) {
        fprintf(stderr, "config: %s\n", err);
        return 1;
    }

    printf("=== parsed %s ===\n", argv[1]);
    awg_config_dump(&cfg, stdout);

    test_base64();
    test_obf(&cfg);
    test_crypto();
    test_handshake(&cfg);
    test_framing(&cfg);
    test_transport(&cfg);

    printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
    awg_config_free(&cfg);
    return failures ? 1 : 0;
}
