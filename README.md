# sys-amneziawg

English · [Русский](README.ru.md)

An AmneziaWG client for the Nintendo Switch, running as an Atmosphère system
module. It takes a configuration exported from the AmneziaVPN client and sends
the hostnames you list through that tunnel. Everything else the console does is
left alone.

The protocol is complete and verified against a live server. Traffic is selected
by hostname; system-wide socket interception is not implemented.

Questions, bug reports and release notes: [t.me/oneth1nq](https://t.me/oneth1nq).

## How it works

Atmosphère's `dns.mitm` answers the hostnames you list with `127.0.0.1`. The
application opens what it thinks is an ordinary connection, and the module
accepts it on port 443. From there the module reads the hostname
out of the TLS ClientHello, resolves it inside the tunnel, connects to the real
server through lwIP and AmneziaWG, and passes the bytes across.

```text
app ── TCP/443 ──▶ sys-amneziawg ──▶ lwIP ──▶ AmneziaWG ──▶ server
                     reads SNI                 encrypts
```

The application sees a normal socket. Every byte between the console and the
AmneziaWG node is encrypted.

## What you need

- A Switch running Atmosphère, with `dns.mitm` available. emuMMC is recommended.
- An AmneziaWG configuration exported from the AmneziaVPN client. `Endpoint`
  must be a literal IPv4 address — a hostname there cannot be resolved before
  the tunnel that would resolve it is up.

Nothing here depends on the console's IP address: the module listens on
loopback, which is the same on every network. Moving between Wi-Fi, the dock's
wired link and a phone hotspot needs no changes.

Back up your SD card before installing any system module.

## Installation

**1. Install the module.** Copy the built `sys-amneziawg.nsp` and `toolbox.json`
to the SD card, and create an empty file to enable autostart:

```text
/atmosphere/contents/4200000000000D92/exefs.nsp     <- sys-amneziawg.nsp, renamed
/atmosphere/contents/4200000000000D92/toolbox.json
/atmosphere/contents/4200000000000D92/flags/boot2.flag
```

`boot2.flag` must exist; its contents do not matter.

**2. Install the tunnel configuration.** In AmneziaVPN, export the connection as
a native WireGuard/AmneziaWG config and save it as:

```text
/config/sys-amneziawg/awg.conf
```

`awg.conf.example` lists every field that is read and the format expected.

**3. List the hostnames.** Copy `hosts.example.txt` to the SD card and add the
hostnames you want tunnelled, each pointing at `127.0.0.1`. The filename
depends on how you boot:

| Setup   | File                                 |
| ------- | ------------------------------------ |
| emuMMC  | `/atmosphere/hosts/emummc_<ID>.txt`  |
| sysNAND | `/atmosphere/hosts/default.txt`      |

`<ID>` is the `id` field from `/emuMMC/emummc.ini`, without the `0x` prefix.
Atmosphère uses the first matching file, so do not leave conflicting ones in
place.

Keep the Nintendo telemetry lines in the example. Atmosphère blocks telemetry by
default, but a hosts file of your own is where that protection tends to get
lost. Those lines point at `127.0.0.1` too, which is a port the module now
answers on — it refuses Nintendo's hostnames by name and counts them as `deny=`
in the log, so the block still holds.

**4. Turn off sleep-mode networking.** In **System Settings → Sleep Mode**,
switch **Keep wired connection in sleep mode** off. Nothing breaks if you leave
it on today, but see [Sleep, and the dock](#sleep-and-the-dock) for why the
habit is worth having now.

**5. Reboot.** The module waits 15 seconds to stay out of the boot's way, waits
for the network, brings the tunnel up and starts logging.

## Checking that it works

The log is at `/config/sys-amneziawg/sys-amneziawg.log`. It is rewritten from
scratch on every boot, so save a copy before rebooting if you need one. A
healthy start looks like this:

```text
boot: network up
console ip: 192.168.1.10
endpoint: 203.0.113.10:51820
timers: rekey 120s, keepalive 30s, retry 7s

[  0s] handshake initial attempt 1: sendto=1261 errno=0
[  0s] session up (handshake #1, rekeys 0)
[  0s] lwip interface up on the tunnel
[  0s] proxy listening on 127.0.0.1:443
        proxy: raw.githubusercontent.com
[ 15s] up=14s tx=1137 rx=1952 ka=0 fetches 1/1 | proxy conns=2 ok=1 fail=0 closed=1 live=0/16 deny=0 full=0 idle=0 up=2KB down=1978KB loops=152 stray=0 replay=0 rebuilds=0 sleep=0
        rate 169KB/s (129 pkt/s) | tcp xmit=1137 recv=1952 drop=0 memerr=0 | ip drop=0 | pbuf err=0
[ 17s] power transition (#1) - dropping the tunnel
[112s] tunnel rebuilt (#2) - new socket, handshaking again
[113s] power transition - tunnel already down, leaving it to the rebuild
[119s] session up (handshake #1, rekeys 0)
```

| Entry                     | Meaning                                                             |
| ------------------------- | ------------------------------------------------------------------- |
| `console ip:`             | The console's own LAN address. Informational; the proxy does not use it. |
| `session up`              | The AmneziaWG handshake succeeded.                                   |
| `proxy listening on 127.0.0.1:443` | The proxy is accepting connections from the console.        |
| `proxy: <host>`           | A hostname read out of a TLS ClientHello and sent through the tunnel.|
| `up= tx= rx= ka=`         | Session age in seconds, then tunnel packets sent, received and keepalives. |
| `fetches N/M`             | A built-in liveness check: N of M test HTTP requests through the tunnel succeeded. |
| `conns / ok / fail / closed` | Proxied connections accepted, finished cleanly, failed to reach the server, and closed for any other reason. The four add up. |
| `live=N/16`               | Slots in use. The table is fixed; at 16/16 new connections are refused. |
| `deny / full / idle`      | Refused by name (Nintendo telemetry), refused because the table was full, and reclaimed after going quiet. |
| `up=KB down=KB`           | Traffic carried by the proxy. The clearest sign that data is moving. |
| `rate`                    | Current throughput. Roughly 200 KB/s is normal.                      |
| `drop / memerr / pbuf err`| Should stay at 0. Anything else means the stack is running short of buffers. |
| `stray=N`                 | Datagrams that arrived from somewhere other than the configured server, and were dropped. Should stay at 0. |
| `replay=N`                | Authenticated datagrams refused because their counter could not be shown to be new. A handful over a long session is ordinary; each one prints a `replay:` line saying whether it was a duplicate or arrived too late to judge. |
| `rebuilds=N` / `sleep=N`  | Tunnels rebuilt, and sleeps noticed. Both climb during normal use — see below. |
| `tunnel socket died`      | The socket stopped working: a sleep, a dropped Wi-Fi link, or a move into the dock. The module rebuilds and handshakes again on its own. |
| `power transition`        | The console slept. The tunnel is dropped and its keys wiped, so no session survives a sleep. If it was already down, the log says so and the rebuild handles it. |
| `no network for Ns`       | Sending was refused for want of a link. After thirty seconds the module spends one rebuild to rule out a socket that will never work. |

A status line is appended every 15 seconds. On shutdown the module writes a
`=== summary ===` and a `=== verdict ===` block with the totals for the run.

## If something does not work

| Symptom                                     | What to check                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Listed hosts do not open at all             | A listed host is unreachable while the tunnel is down. Check `session up` in the log.            |
| No log file                                 | `awg.conf` missing or in the wrong place, or `boot2.flag` missing, so the module never started.  |
| Log stops at `boot: waiting for the network`| The console never reported a working connection. Check Wi-Fi and reboot.                         |
| `handshake ... attempt N` repeats           | The endpoint is unreachable, or the keys and obfuscation values do not match the server.         |
| `proxy FAILED to bind :443`                 | Another module or application already holds port 443. Disable it.                                |
| Listed hosts stop working after a while     | Check `live=` in the log. At `16/16` the table is full and `full=` is climbing; report it.       |
| Hosts file gone after a reboot              | Some bootloader packages overwrite `default.txt`. On emuMMC use the filename with your emuMMC ID.|
| Nothing works for a moment after sleep      | The tunnel rebuilds itself, but Wi-Fi takes a few seconds to come back. Give it half a minute before rebooting. |
| A long gap between log entries              | The console was asleep; every process is frozen, this one included. The lines either side of the gap say `power transition`.                     |
| Listed hosts fail while docked and asleep   | Expected. Turn off **System Settings → Sleep Mode → Keep wired connection in sleep mode**; see below.                                            |

To go back to normal behaviour, delete or rename the hosts file. Nothing else
needs to be touched.

## Limitations

- TCP on port 443 only. UDP and QUIC are not carried.
- Only the hostnames in the hosts file. All other traffic is untouched.
- One server per configuration: no switching on the fly, no subscriptions.
- The tunnel is dropped on sleep and rebuilt on wake; nothing runs while the
  console is asleep. Keep wired connection in sleep mode should be off — see
  below.
- No overlay or interface; state goes to the log file.
- Throughput depends on the server, Wi-Fi and tunnel settings. Around 200 KB/s
  is what this build currently reaches.

### Sleep, and the dock

**Turn off System Settings → Sleep Mode → Keep wired connection in sleep mode
while you use this module.**

Every system module is frozen while the console sleeps, this one included. The
module drops the tunnel as soon as it notices a power transition — the keys are
wiped, the socket is closed, and a fresh handshake runs on the next wake — so a
session never quietly survives a sleep it could not watch.

Nothing leaks with the setting either way. The hostnames you listed still
resolve to `127.0.0.1`, and with the module frozen those connections fail rather
than going out around the tunnel. Downloads from the eShop are unaffected: they
go to Nintendo servers, which the hosts file does not redirect.

So today the setting costs you nothing but a failed connection, and the advice
above is a recommendation rather than a requirement. It is here so the habit is
already in place before it matters. Once traffic is captured at the socket level
instead of by hostname, a frozen module will mean a frozen network for the whole
console — and that is exactly the case where the console would otherwise be
awake and using it.

## Building

Requires devkitPro with devkitA64 and libnx.

The module asks for `pdm:qry` in `sys-amneziawg.json`, which is how it
notices that the console slept. Removing it from the service list costs
nothing else, but sleep then goes unnoticed and the tunnel is only rebuilt
once its socket dies.

```sh
export DEVKITPRO=/opt/devkitpro
make
```

This produces `sys-amneziawg.nsp`. `make clean` removes the build output.

On Windows, build from the MSYS2 shell that ships with devkitPro. If the
assembler cannot create temporary files, set the directory explicitly, one
variable per command:

```sh
export DEVKITPRO=/c/devkitPro
export TMPDIR=/c/Users/<user>/AppData/Local/Temp
export TMP=$TMPDIR
export TEMP=$TMPDIR
make
```

The vendored crypto code produces compiler warnings. Warnings from unmodified
files under `source/crypto/` are expected and are not a fault in this project.

### Host test harness

The protocol core also builds for an ordinary computer, which is how it was
developed:

```sh
clang -std=gnu11 -Isource -o awg-host \
    source/awg_obf.c source/awg_config.c source/awg_rand.c \
    source/awg_noise.c source/awg_ipprobe.c source/main_host.c \
    source/crypto/*.c
./awg-host awg.conf
```

It runs the RFC test vectors for BLAKE2s and X25519, a full handshake between
an initiator and a responder, and transport packets — no console and no network
required.

## Repository layout

| Path                    | Contents                                                     |
| ----------------------- | ------------------------------------------------------------ |
| `source/awg_noise.c`    | Noise_IKpsk2 handshake and transport encryption.              |
| `source/awg_obf.c`      | AmneziaWG obfuscation: junk packets and the I1–I5 templates.  |
| `source/awg_config.c`   | `.conf` parser.                                               |
| `source/awg_session.c`  | Session state, timers, key rotation, keepalives.              |
| `source/awg_netif.c`    | The lwIP network interface sitting on the tunnel.             |
| `source/awg_power.c`    | Notices that the console slept, by reading the play-event log.|
| `source/awg_proxy.c`    | The SNI proxy between console sockets and lwIP.               |
| `source/main_switch.c`  | System module entry point, main loop and logging.             |
| `source/main_host.c`    | Host harness entry point.                                     |
| `source/awg_ipprobe.c`  | Minimal IP/UDP/DNS used by the harness.                       |
| `source/lwip/`, `source/lwip_port/` | Vendored lwIP and its port layer.                 |
| `source/crypto/`        | Vendored BLAKE2s, ChaCha20, Poly1305 and X25519.              |
| `awg.conf.example`      | Configuration template, no real keys.                         |
| `hosts.example.txt`     | Hosts file template.                                          |

## Security

`awg.conf` holds a working private key and grants full access to your tunnel.
Keep it on a trusted SD card and never publish it — not in issues, not in logs,
not in archives. It is excluded by `.gitignore`.

Session keys are never written to the log.

**The log records every hostname you visit through the tunnel.** That is a list
of the sites the console opened, and it is there because the module is still
being debugged. Read it before sending it to anyone, and strip the `proxy:`
lines if you would rather not share your browsing. The log is rewritten from
scratch on every boot, so it never grows into a long history.

## Credits

Written by alik. Parts of the implementation were done together with Claude, an
AI assistant made by Anthropic.

Releases and discussion: [t.me/oneth1nq](https://t.me/oneth1nq) — the channel
carries release notes, and its comments and direct messages are open.

## License

GNU Affero General Public License v3.0. See `LICENSE` and `NOTICE`.

Vendored components (lwIP, the cryptographic primitives) are distributed under
their own BSD licenses; see `NOTICE`.
