# sys-amneziawg

English · [Русский](README.ru.md)

An AmneziaWG VPN client for Nintendo Switch, running as an Atmosphère system
module. It takes the configuration you export from the AmneziaVPN client and
routes selected traffic through that tunnel.

**Status: beta (v0.0.1).** The protocol is complete and verified against a live
server. Traffic selection is hostname-based; system-wide socket interception is
not implemented.

## What works

- AmneziaWG 3.1: obfuscated handshake, header protection, junk packets, key
  rotation, keepalives
- A TCP/IP stack (lwIP) running over the tunnel
- Transparent proxying of listed hostnames, selected by TLS SNI
- Measured throughput ~200 KB/s; DNS is resolved inside the tunnel

## What does not

- Only TCP on port 443. UDP and QUIC are not carried.
- Only hostnames listed in the `dns.mitm` hosts file. Traffic to anything else
  is untouched.
- One server per configuration; no switching at runtime, no subscriptions.
- Sleep and resume are detected but not optimised.
- No overlay or UI. Status is written to a log file.

## How it works

`dns.mitm` points the listed hostnames at the console's own address. The module
listens on port 443, reads the hostname from the TLS ClientHello, resolves it
through the tunnel, and relays the connection. The application sees an ordinary
socket; every byte travels encrypted to the AmneziaWG peer.

## Requirements

- Atmosphère CFW, emuMMC recommended
- An AmneziaWG configuration with a literal IPv4 endpoint
- A reserved (static) DHCP lease for the console

## Installation

1. Copy `sys-amneziawg.nsp` to the SD card as:

   ```
   /atmosphere/contents/4200000000000D92/exefs.nsp
   ```

2. Copy `toolbox.json` to:

   ```
   /atmosphere/contents/4200000000000D92/toolbox.json
   ```

3. Create an empty file to start the module at boot:

   ```
   /atmosphere/contents/4200000000000D92/flags/boot2.flag
   ```

4. Export your AmneziaWG configuration from the AmneziaVPN client and copy it
   to:

   ```
   /config/sys-amneziawg/awg.conf
   ```

   See `awg.conf.example` for the accepted fields. `Endpoint` must be a literal
   IPv4 address.

5. Find the console's LAN address (System Settings → Internet → Connection
   Status) and reserve it on the router.

6. Copy `hosts.example.txt` to `/atmosphere/hosts/emummc_XXXXXXXX.txt`, where
   `XXXXXXXX` is the `id` field from `/emuMMC/emummc.ini` without the `0x`
   prefix. On sysNAND, use `default.txt` instead. Replace `192.168.1.10` in the
   file with the console's address, and list the hostnames you want tunnelled.

7. Reboot. The module waits 15 seconds, connects, and writes
   `/config/sys-amneziawg/sys-amneziawg.log`.

## Verifying

The log reports the tunnel state and each proxied connection:

```
boot: network up
[  0s] session up (handshake #1, rekeys 0)
[  0s] proxy listening on :443
        proxy: raw.githubusercontent.com
[ 15s] up=14s tx=1137 rx=1952 | proxy conns=2 ok=1 fail=0 up=2KB down=1978KB
        rate 169KB/s (129 pkt/s) | tcp xmit=1137 recv=1952 drop=0
```

If a hostname is listed but the tunnel is down, that hostname is unreachable.
Removing the hosts file restores normal behaviour.

## Security

- `awg.conf` contains a live private key. It is excluded by `.gitignore`;
  do not publish it.
- Nintendo telemetry blocking is preserved in the example hosts file. Keep
  those two lines.
- Session keys are never written to the log.

## Building

Requires devkitPro with devkitA64 and libnx.

```sh
export DEVKITPRO=/opt/devkitpro
make
```

`make` also builds nothing else; the host-side test harness is built manually:

```sh
clang -std=gnu11 -Isource -o awg-host \
    source/awg_obf.c source/awg_config.c source/awg_rand.c \
    source/awg_noise.c source/awg_ipprobe.c source/main_host.c \
    source/crypto/*.c
./awg-host awg.conf
```

The harness runs RFC test vectors for BLAKE2s and X25519, a full handshake
between an initiator and a responder, and transport round-trips — without
touching the network.

## Credits

Written by alik. Parts of the implementation were developed together with
Claude, an AI assistant by Anthropic.

## Licence

GNU Affero General Public License v3.0. See `LICENSE` and `NOTICE`.

Third-party components (lwIP, cryptographic primitives) retain their own BSD
licences; see `NOTICE`.
