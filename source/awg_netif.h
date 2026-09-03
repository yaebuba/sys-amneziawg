/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * The tunnel as an lwIP network interface.
 *
 * lwIP normally drives an ethernet controller. Here its "hardware" is the
 * AmneziaWG session: packets it wants to transmit are sealed and sent to the
 * peer, and packets that arrive from the peer are injected back into it.
 *
 * That gives us a real TCP/IP stack whose traffic happens to travel through
 * the tunnel - which is what stage 5 needs, because intercepted socket calls
 * have to be turned into connections somewhere, and Horizon will not do it
 * for us.
 */
#ifndef SYS_AWG_NETIF_H
#define SYS_AWG_NETIF_H

#include "awg.h"
#include "awg_session.h"

/*
 * Brings up lwIP and attaches the tunnel interface, using the address from
 * the config. `fd` is the UDP socket the session sends on and `peer` the
 * endpoint to send to; both must outlive the interface.
 *
 * Returns 0 on success.
 */
int awg_netif_start(const awg_config *cfg, awg_session *sess,
                    int fd, const void *peer_sockaddr, int peer_len);

/* Hands a decrypted inner IP packet to the stack. */
/*
 * Hands the interface a replacement socket after the old one dies.
 *
 * Deliberately not awg_netif_start() again: that calls lwip_init() and
 * netif_add(), and doing either a second time on a running stack corrupts it.
 * Only the descriptor underneath changes when a suspend or a lost link takes
 * the socket away - the interface, its address and every pcb on it are still
 * perfectly good.
 */
void awg_netif_set_fd(int fd);

void awg_netif_input(const uint8_t *packet, int len);

/*
 * Must be called regularly from the main loop. lwIP has no threads here, so
 * its retransmissions and timers only advance when we say so - a stack that
 * is not ticked looks exactly like a network that has gone silent.
 */
void awg_netif_poll(void);

/* True once the interface is up. */
bool awg_netif_ready(void);

#endif /* SYS_AWG_NETIF_H */
