/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * Power transitions, read out of the play-event log. See awg_power.h for why
 * this is not psc:m.
 */
#include <string.h>
#include <switch.h>

#include "awg_power.h"

/* How far back a single query reaches. The log advances by a handful of
 * entries around a suspend, so this is generous; entries older than the
 * window are lost, which costs us nothing we would have acted on twice. */
#define EVENT_BATCH 16

static bool g_ok        = false;
static s32  g_last_end  = -1;   /* index of the newest entry already read */

bool awg_power_start(void)
{
    if (R_FAILED(pdmqryInitialize())) return false;

    /*
     * pdm:qry hands out three sessions to user-land and libnx holds one of
     * them live. Query commands do not need a live session, so clone the
     * handle and close the original: a service this module only reads from
     * should not occupy a slot another process may need.
     */
    Service *srv = pdmqryGetServiceSession();
    Service  clone;
    if (R_FAILED(serviceClone(srv, &clone))) {
        pdmqryExit();
        return false;
    }
    serviceClose(srv);
    memcpy(srv, &clone, sizeof(Service));

    g_ok       = true;
    g_last_end = -1;
    return true;
}

void awg_power_stop(void)
{
    if (!g_ok) return;
    pdmqryExit();
    g_ok = false;
}

bool awg_power_transition(void)
{
    if (!g_ok) return false;

    s32 total = 0, first = 0, last = 0;
    if (R_FAILED(pdmqryGetAvailablePlayEventRange(&total, &first, &last)))
        return false;

    if (last <= g_last_end) return false;         /* nothing new */

    /*
     * The first look only marks where the log stands. Entries written before
     * this module started describe a console we were not watching, and
     * replaying them as if they had just happened would tear down a tunnel
     * that is working.
     */
    if (g_last_end < 0) {
        g_last_end = last;
        return false;
    }

    s32 from = g_last_end + 1;
    if (from < last - (EVENT_BATCH - 1)) from = last - (EVENT_BATCH - 1);
    if (from < first) from = first;
    if (from < 0)     from = 0;

    s32 want = last - from + 1;
    if (want > EVENT_BATCH) want = EVENT_BATCH;
    if (want <= 0) { g_last_end = last; return false; }

    PdmPlayEvent events[EVENT_BATCH];
    s32 got = 0;
    if (R_FAILED(pdmqryQueryPlayEvent(from, events, want, &got)))
        return false;                             /* retry on the next tick */

    g_last_end = last;

    /*
     * Sleep and wake are not told apart. The `value` byte that would
     * distinguish them is undocumented, and both edges call for the same
     * response here: whatever happened, the tunnel was left running while
     * nobody was watching it.
     */
    for (s32 i = 0; i < got; i++)
        if (events[i].play_event_type == PdmPlayEventType_PowerStateChange)
            return true;

    return false;
}
