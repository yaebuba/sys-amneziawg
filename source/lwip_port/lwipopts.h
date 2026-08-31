/*
 * Copyright (c) 2026 alik <yaebubas@gmail.com>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Part of sys-amneziawg. See LICENSE for the full terms.
 */
/*
 * lwIP configuration for sys-amneziawg.
 *
 * This stack does not drive hardware. Its network interface is the tunnel:
 * packets it emits are sealed into AmneziaWG datagrams, and packets that come
 * back are injected into it. That removes whole subsystems - there is no
 * ethernet, no ARP, no DHCP - and what is left has to be small, because a
 * sysmodule shares the system memory pool with everything else the console
 * runs.
 */
#ifndef SYS_AWG_LWIPOPTS_H
#define SYS_AWG_LWIPOPTS_H

/* No OS abstraction: one thread drives the stack and calls the timer tick
 * itself. Threads and mailboxes would buy nothing here and cost memory. */
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0

/* The raw callback API only. The socket and netconn layers exist to imitate
 * BSD sockets, and we are the ones being asked for BSD sockets. */
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_NETIF_API              0

#define LWIP_IPV4                   1
#define LWIP_IPV6                   0

#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_RAW                    1
#define LWIP_ICMP                   1
#define LWIP_IGMP                   0

/* The interface is point-to-point, so there is no link layer to resolve. */
#define LWIP_ARP                    0
#define LWIP_ETHERNET               0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_NETIF_HOSTNAME         0
#define LWIP_NETIF_STATUS_CALLBACK  0
#define LWIP_NETIF_LINK_CALLBACK    0

/*
 * Names are resolved through the tunnel, by lwIP, using the resolver from the
 * config. Doing it here rather than over the console's own stack matters: a
 * lookup that leaks outside the tunnel would be answered by the ISP, and in
 * this country that is the answer we are trying to get away from.
 */
#define LWIP_DNS                    1

/*
 * The resolver needs randomness for transaction ids and source ports, and it
 * has to be unpredictable: a guessable id is what lets someone else answer
 * our lookups before the real server does. Backed by the platform CSPRNG.
 */
unsigned int lwip_port_rand(void);
#define LWIP_RAND() ((u32_t)lwip_port_rand())
#define DNS_TABLE_SIZE              8
#define DNS_MAX_NAME_LENGTH         128

/* Memory. These are the numbers to revisit if throughput disappoints or the
 * console starts refusing to allocate; they are sized for a handful of
 * concurrent connections, not for a desktop. */
#define MEM_LIBC_MALLOC             0
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (48 * 1024)

#define MEMP_NUM_PBUF               16
#define MEMP_NUM_TCP_PCB            12
#define MEMP_NUM_TCP_PCB_LISTEN     4
#define MEMP_NUM_TCP_SEG            64
#define MEMP_NUM_UDP_PCB            8
#define MEMP_NUM_RAW_PCB            2
#define MEMP_NUM_SYS_TIMEOUT        8

#define PBUF_POOL_SIZE              24

/*
 * MTU. An ethernet frame leaves 1500 bytes; the tunnel spends 28 on the outer
 * IPv4/UDP headers and another 44 on AmneziaWG's own framing (12 bytes of S4
 * padding, a 16-byte header and the 16-byte AEAD tag). 1400 leaves room to
 * spare, which matters because a path that silently drops oversized packets
 * is miserable to diagnose.
 */
#define TCP_MSS                     1360
#define PBUF_POOL_BUFSIZE           1500

#define TCP_SND_BUF                 (16 * TCP_MSS)
#define TCP_WND                     (16 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * TCP_SND_BUF) / TCP_MSS)

#define LWIP_CHECKSUM_CTRL_PER_NETIF 0

/* Statistics and asserts cost space; keep the counters, drop the prose. */
#define LWIP_STATS                  1
#define LWIP_STATS_DISPLAY          0
#define LWIP_DEBUG                  0

/* Horizon's newlib provides these; without saying so lwIP defines its own
 * and the two collide at link time. */
#define LWIP_TIMEVAL_PRIVATE        0
#define LWIP_ERRNO_STDINCLUDE       1

#endif /* SYS_AWG_LWIPOPTS_H */
