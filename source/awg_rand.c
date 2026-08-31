/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Platform services: entropy and wall-clock time.
 *
 * Both backends for randomness are CSPRNGs - WireGuard's security rests on
 * the ephemeral keys, and the junk bytes must not be predictable either or
 * the obfuscation becomes its own signature.
 */
#include "awg.h"

#ifdef __SWITCH__

#include <switch.h>
#include <time.h>

void awg_random_bytes(void *dst, size_t n)
{
    randomGet(dst, n);
}

uint64_t awg_now_seconds(void)
{
    u64 ts = 0;

    /* The network clock is the one that has been corrected against Nintendo's
     * time servers; the user clock can be set to anything. Fall back through
     * the others so a console that has never been online still gets its best
     * available guess rather than 1970. */
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_NetworkSystemClock, &ts)) && ts)
        return ts;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_UserSystemClock, &ts)) && ts)
        return ts;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_Default, &ts)) && ts)
        return ts;

    return (uint64_t)time(NULL);
}

#else

#include <stdlib.h>
#include <time.h>

void awg_random_bytes(void *dst, size_t n)
{
    arc4random_buf(dst, n);
}

uint64_t awg_now_seconds(void)
{
    return (uint64_t)time(NULL);
}

#endif
