/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
#ifndef AWG_POWER_H
#define AWG_POWER_H

#include <stdbool.h>

/*
 * Noticing that the console went to sleep.
 *
 * WHY NOT psc:m. The documented way to hear about suspend is to register a
 * psc:m module and answer its state requests. We tried it and it hung the
 * console: a registered module that fails to acknowledge ReadySleep stalls the
 * suspend path, and this module must never be able to wedge sleep.
 *
 * The play-event log records the same transitions as ordinary entries. Reading
 * it costs one query per second, blocks nothing, and cannot be waited on by
 * anything else.
 *
 * The signal arrives late. Every process is frozen shortly after the console
 * begins to suspend, so in the common case the entry is only seen once the
 * console is awake again. That is still worth acting on: it says the tunnel
 * spent an unknown stretch of time unattended, which is exactly when its keys
 * and counters must not be trusted.
 */

/* Best effort. Returns false if the play-event log is unavailable, in which
 * case sleep goes unnoticed and recovery falls back to the socket dying. */
bool awg_power_start(void);

void awg_power_stop(void);

/* True once for each power transition recorded since the previous call. */
bool awg_power_transition(void);

#endif /* AWG_POWER_H */
