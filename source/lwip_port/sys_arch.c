/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * The whole of the OS abstraction lwIP needs when NO_SYS is 1: a millisecond
 * clock for its timers. Everything else - threads, semaphores, mailboxes -
 * belongs to the modes we are not using.
 */
#include <switch.h>

#include "lwip/arch.h"
#include "awg.h"

u32_t sys_now(void)
{
    /* Monotonic, and unaffected by the console's wall clock being wrong or
     * jumping when it resumes from sleep. Wrapping after 49 days is fine:
     * lwIP compares timestamps with subtraction, which survives the wrap. */
    return (u32_t)(armTicksToNs(armGetSystemTick()) / 1000000ULL);
}

unsigned int lwip_port_rand(void)
{
    unsigned int v;
    awg_random_bytes(&v, sizeof(v));
    return v;
}
