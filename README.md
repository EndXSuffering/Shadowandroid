# Shadow Firewall

An Android app that shows you every connection your apps make, and blocks the ones you don't
want. No root required.

- **See traffic** — a live log of every connection, attributed to the app that made it, with
  the hostname, port, verdict and byte counts.
- **Block per app** — separate Wi-Fi and mobile-data switches for each installed app.
- **Block per domain** — a suffix-matched blocklist (`doubleclick.net` also covers
  `ad.doubleclick.net`), with an allowlist that overrides it.
- **Block by default** — optional deny-everything-unless-allowed policy.

## How it works

Android gives a non-rooted app exactly one way to see another app's traffic: become the
device's VPN. So the app registers a `VpnService`, and the system routes every packet through
a tun interface that this process owns.

Nothing is sent to a remote server. The "VPN" terminates on the device.

```
   app socket
       │
       ▼
 ┌───────────┐   packets    ┌──────────────┐   verdict   ┌────────────┐
 │ tun device├─────────────►│ TunnelRelay  ├────────────►│ RuleEngine │
 └───────────┘              └──────┬───────┘             └────────────┘
       ▲                           │ allowed
       │  spoofed reply packets    ▼
       │                    ┌──────────────┐   protect() so it uses the
       └────────────────────┤ TcpFlow /    ├── real network, not our tunnel
                            │ UdpFlow      │
                            └──────┬───────┘
                                   ▼
                              real internet
```

For an allowed flow the relay opens a *separate* socket, calls `VpnService.protect()` on it so
it bypasses the tunnel, and shuttles bytes between that socket and the tun device. That means
implementing enough of TCP in userspace to satisfy the app on the other side: the handshake,
in-order data transfer, flow control in both directions, and orderly and abortive close. There
is no congestion control and no retransmission toward the app, because the tun device is a
local queue rather than a lossy link.

For a blocked flow, TCP gets an immediate RST — apps fail fast instead of hanging until their
own timeout — and UDP is dropped silently, which is what a UDP sender already expects.

**Per-app attribution** uses `ConnectivityManager.getConnectionOwnerUid`, which the platform
exposes to the active VPN app. That API is why the minimum is Android 10 (API 29); on older
releases the only route was reading `/proc/net/tcp`, which third-party apps lost access to.

**Domain rules** work by watching plain DNS on port 53. Queries for a blocked name are answered
with NXDOMAIN and never forwarded; responses for everything else are parsed so the traffic log
can show hostnames instead of bare IPs.

## Limitations

Worth knowing before you rely on it:

- **DNS over HTTPS/TLS bypasses domain rules.** If an app resolves names over HTTPS (Chrome and
  Firefox do by default), the firewall never sees the query. Per-app rules still apply, because
  they act on the connection rather than the lookup — that is the reliable layer.
- **Only one VPN can be active at a time.** Turning this on displaces any other VPN.
- **ICMP is dropped**, so `ping` will not work while the tunnel is up. Relaying it needs a raw
  socket, which a non-rooted app cannot open.
- **IP fragments are dropped** rather than reassembled.
- Turning on *Block IPv6* rebuilds the tunnel without IPv6 routes, so apps fall back to IPv4.
- The traffic log lives in memory only and is capped at 1000 entries. It is deliberately not
  written to disk — a persistent record of every connection a phone makes is a more sensitive
  artefact than this app is worth.

## Building

```bash
./gradlew :app:assembleDebug     # APK at app/build/outputs/apk/debug/
./gradlew test                   # unit tests for the packet and rule logic
```

Requires JDK 17 and the Android SDK (compileSdk 35).

## Layout

| Module | What's in it |
| --- | --- |
| `core/` | Pure-JVM logic: IPv4/IPv6 and TCP/UDP parsing and construction, checksums, DNS, the rule engine, the hostname cache. No Android dependencies, so it is unit tested on the desktop JVM. |
| `app/` | The Android app: `VpnService`, the relay and its flows, rule persistence, and the Compose UI. |

The split is deliberate. Packet handling and rule matching are the easiest parts of a firewall
to get subtly wrong and the hardest to debug on a device, so they live where a plain
`./gradlew test` can cover them.

### Key files

| File | Role |
| --- | --- |
| `core/…/IpPacket.kt` | Zero-copy parsing of IP/TCP/UDP headers |
| `core/…/PacketFactory.kt` | Builds the packets sent back to apps, and all checksums |
| `core/…/Rules.kt` | The verdict logic |
| `core/…/Dns.kt` | Query/response parsing and NXDOMAIN synthesis |
| `app/…/vpn/TunnelRelay.kt` | Reads the tun device, applies verdicts, owns the flow table |
| `app/…/vpn/TcpFlow.kt` | The userspace TCP state machine |
| `app/…/vpn/SelectorLoop.kt` | One NIO selector thread driving every relayed socket |
| `app/…/vpn/FirewallVpnService.kt` | Tunnel setup and service lifecycle |

## Testing status

`core/` has 47 unit tests covering checksums, IPv4 and IPv6 round trips, sequence-number
wrapping, RST generation, DNS parsing (including compression-pointer loops and truncated
input), suffix matching, and cache expiry. Run them with `./gradlew :core:test`.

The `app/` module has no automated tests yet. The relay's behaviour under real traffic —
handshakes, flow control, teardown — has not been exercised against a device.
