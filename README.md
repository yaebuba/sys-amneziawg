# sys-amneziawg

English · [Русский](README.ru.md)

An AmneziaWG client for the Nintendo Switch, running as an Atmosphère system
module. It takes a configuration exported from the AmneziaVPN client and sends
the hostnames you list through that tunnel. Everything else the console does is
left alone.

**Status: beta (v0.0.1).** The protocol is complete and verified against a live
server. Traffic is selected by hostname; system-wide socket interception is not
implemented.

## How it works

Atmosphère's `dns.mitm` answers the hostnames you list with the console's own
LAN address. The application opens what it thinks is an ordinary connection,
and the module accepts it on port 443. From there the module reads the hostname
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
- A fixed LAN address for the console, reserved on the router. A new DHCP lease
  breaks the hosts file silently.

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

**3. Fix the console's address.** Find it under Settings → Internet →
Connection Status, then reserve it for the console on your router.

**4. List the hostnames.** Copy `hosts.example.txt` to the SD card, replacing
`192.168.1.10` with the console's address and listing the hostnames you want
tunnelled. The filename depends on how you boot:

| Setup   | File                                 |
| ------- | ------------------------------------ |
| emuMMC  | `/atmosphere/hosts/emummc_<ID>.txt`  |
| sysNAND | `/atmosphere/hosts/default.txt`      |

`<ID>` is the `id` field from `/emuMMC/emummc.ini`, without the `0x` prefix.
Atmosphère uses the first matching file, so do not leave conflicting ones in
place.

Keep the Nintendo telemetry lines in the example. Atmosphère blocks telemetry by
default, but a hosts file of your own is where that protection tends to get
lost.

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

[  0s] handshake initial attempt 1: sendto=1261
[  0s] session up (handshake #1, rekeys 0)
[  0s] lwip interface up on the tunnel
[  0s] proxy listening on :443
        proxy: raw.githubusercontent.com
[ 15s] up=14s tx=1137 rx=1952 ka=0 fetches 1/1 | proxy conns=2 ok=1 fail=0 up=2KB down=1978KB
        rate 169KB/s (129 pkt/s) | tcp xmit=1137 recv=1952 drop=0 memerr=0 | ip drop=0 | pbuf err=0
```

| Entry                     | Meaning                                                             |
| ------------------------- | ------------------------------------------------------------------- |
| `console ip:`             | Where the module accepts connections. Must match your hosts file.    |
| `session up`              | The AmneziaWG handshake succeeded.                                   |
| `proxy listening on :443` | The proxy is accepting connections from the console.                 |
| `proxy: <host>`           | A hostname read out of a TLS ClientHello and sent through the tunnel.|
| `up= tx= rx= ka=`         | Session age in seconds, then tunnel packets sent, received and keepalives. |
| `fetches N/M`             | A built-in liveness check: N of M test HTTP requests through the tunnel succeeded. |
| `conns / ok / fail`       | Proxied connections accepted, completed and failed.                  |
| `up=KB down=KB`           | Traffic carried by the proxy. The clearest sign that data is moving. |
| `rate`                    | Current throughput. Roughly 200 KB/s is normal.                      |
| `drop / memerr / pbuf err`| Should stay at 0. Anything else means the stack is running short of buffers. |

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
| Hosts file gone after a reboot              | Some bootloader packages overwrite `default.txt`. On emuMMC use the filename with your emuMMC ID.|
| Nothing works after sleep                   | Sleep and wake are detected but not yet optimised. Reboot fully.                                 |

To go back to normal behaviour, delete or rename the hosts file. Nothing else
needs to be touched.

## Limitations

- TCP on port 443 only. UDP and QUIC are not carried.
- Only the hostnames in the hosts file. All other traffic is untouched.
- One server per configuration: no switching on the fly, no subscriptions.
- Sleep and wake are detected but not yet optimised.
- No overlay or interface; state goes to the log file.
- Throughput depends on the server, Wi-Fi and tunnel settings. Around 200 KB/s
  is what this build currently reaches.

## Building

Requires devkitPro with devkitA64 and libnx.

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

## Credits

Written by alik. Parts of the implementation were done together with Claude, an
AI assistant made by Anthropic.

## License

GNU Affero General Public License v3.0. See `LICENSE` and `NOTICE`.

Vendored components (lwIP, the cryptographic primitives) are distributed under
their own BSD licenses; see `NOTICE`.
