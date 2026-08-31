/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * lwIP architecture bindings for devkitA64 / Horizon.
 *
 * aarch64 with newlib gives us everything lwIP asks for through the standard
 * headers, so this file is mostly a matter of pointing lwIP at them.
 */
#ifndef SYS_AWG_LWIP_ARCH_CC_H
#define SYS_AWG_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * newlib declares ssize_t but does not always define SSIZE_MAX, and lwIP
 * reads the absence of that macro as "no ssize_t here" and defines its own -
 * as int, which then collides with newlib's long. Defining it settles the
 * question before lwIP asks.
 */
#ifndef SSIZE_MAX
#define SSIZE_MAX __LONG_MAX__
#endif

/* The Switch is little-endian. */
#define BYTE_ORDER LITTLE_ENDIAN

/* Packing: the compiler is GCC, so use its attributes. */
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

/*
 * lwIP calls this when an assertion fails. A sysmodule has no console to
 * print to and aborting would take the whole system down over what is often
 * a recoverable packet problem, so the failure is swallowed here and the
 * caller is left to carry on. If lwIP starts misbehaving this is the first
 * place to add logging.
 */
#define LWIP_PLATFORM_DIAG(x)   do { } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { } while (0)

#endif /* SYS_AWG_LWIP_ARCH_CC_H */
