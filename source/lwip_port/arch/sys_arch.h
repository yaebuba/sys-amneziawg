/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * With NO_SYS set, lwIP wants this header to exist but takes nothing from it
 * beyond the protection type - there are no threads to guard against, since
 * one thread owns the stack and calls sys_check_timeouts() itself.
 */
#ifndef SYS_AWG_LWIP_ARCH_SYS_ARCH_H
#define SYS_AWG_LWIP_ARCH_SYS_ARCH_H

typedef int sys_prot_t;

#endif /* SYS_AWG_LWIP_ARCH_SYS_ARCH_H */
