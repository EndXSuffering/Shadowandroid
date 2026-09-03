# Shadow Firewall

[![Build APK](https://github.com/EndXSuffering/Shadowandroid/actions/workflows/build.yml/badge.svg)](https://github.com/EndXSuffering/Shadowandroid/actions/workflows/build.yml)

An Android app that shows you every connection your apps make, and blocks the ones you don't
want. No root required.

- **See traffic** — a live log of every connection, attributed to the app that made it, with
  the hostname, port, verdict and byte counts.
- **Block per app** — separate Wi-Fi and mobile-data switches for each installed app.
- **Block per domain** — a suffix-matched blocklist (`doubleclick.net` also covers
  `ad.doubleclick.net`), with an allowlist that overrides it.
- **Subscribed ad, tracker and malware lists** — curated third-party lists that refresh in
  the background, on by default.
- **Two tracker levels** — *Balanced* blocks telemetry without breaking apps; *Full* goes
  after attribution and measurement too.
- **Block by default** — optional deny-everything-unless-allowed policy.

👉 **Just want it on your phone? Go to [Installing](#installing).**

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

Not every connection can be traced back to an installed app, and the reasons differ enough to
be worth telling apart. Android's own daemons own no package — the DNS resolver carries every
lookup on the device and appears as uid 1051 — sandboxed browser renderers own no package, an
app uninstalled since the connection was logged no longer has one, and a uid from a work
profile carries a 100000 offset. The log names each of those rather than calling them all
unknown. A connection whose owner the kernel could not report at all is labelled
*Unattributed*, which usually means the socket closed before the lookup could match it.

**Domain rules** are enforced against the DNS query, not the connection. A query for a blocked
name is answered with NXDOMAIN and never forwarded; responses for everything else are parsed so
the traffic log can show hostnames instead of bare IPs.

That distinction matters. The IP-to-hostname map built from those responses is only ever used
for *display*, never to decide a block. One address routinely serves many names — claude.ai and
a blocked tracker can share a Cloudflare address, a storefront and its ad subdomain share a
CloudFront one — so the last name seen for an address says nothing reliable about the next
connection to it. Blocking on that reverse lookup silently takes down whatever else lives on the
same CDN.

## Ad and malware lists

Out of the box the app subscribes to a set of maintained lists and refreshes them daily:

| List | Category | Approximate size | Default |
| --- | --- | --- | --- |
| AdGuard DNS filter | Ads and tracking | 154,000 | on |
| Phishing Army | Phishing | 156,000 | on |
| ShadowWhisperer's malware list | Malware | 43,000 | on |
| Dandelion Sprout's anti-malware list | Malware | 12,000 | on |
| Scam blocklist | Scams | 1,000 | on |
| AdGuard popup hosts | Ads | 1,000 | off |
| StevenBlack unified hosts | Ads and malware | 98,000 | off |
| HaGeZi threat intelligence feeds | Malware | 2,200,000 | off |

They come from the [AdGuard hostlists registry](https://github.com/AdguardTeam/HostlistsRegistry),
which mirrors the upstream lists at stable URLs in one consistent format, so the app needs one
parser and one host it depends on rather than a dozen of each. StevenBlack's hosts file is
taken from its own repository as the canonical example of that format.

**Memory.** A `HashSet<String>` of two million domains costs about 180 MB, which no phone will
tolerate for a background service. Domains are stored instead as sorted 64-bit hashes — 8 bytes
each, looked up by binary search — so the default set of lists is about 3 MB and even the
2.2-million-entry threat feed fits in 18 MB. The cost is that a hash collision would block a
domain that is not on the list; at these sizes that is around a one-in-ten-million chance, well
under the false-positive rate of the lists themselves, and the user's allowlist always wins.

**IP-address rules.** Malware lists carry entries like `||109.201.135.46^` for hosts reached
without any lookup. Because this firewall sees the destination address of every connection, it
enforces those directly — the one part of a list that DNS-over-HTTPS cannot route around.

**What is not imported.** Rules that cannot be honoured at this level are dropped rather than
approximated: regular expressions, cosmetic rules, partial wildcards like
`ad-host-*.example.com`, path rules such as `||example.com/ads/banner.png`, and rules carrying
modifiers that narrow them (`$denyallow`, `$client`, `$dnstype`). Blocking the whole host for a
path rule would take down the site. In practice this drops well under 1% of a typical list.

Every list can be switched off individually, the whole feature has a master switch, and
refreshes can be limited to Wi‑Fi or set to manual only.

## Tracker blocking

Two levels, and they are not the same list turned up louder — they are different kinds of
endpoint.

**Balanced** blocks analytics and phone-maker telemetry: the requests an app fires and never
reads a reply to. Losing them is not something an app notices. This is Samsung, Xiaomi, OPPO,
Realme and Vivo reporting, plus ShadowWhisperer's tracking list and Peter Lowe's.

**Full** adds attribution, measurement and consent services. Some apps genuinely wait on these
before they will show content, so this level will occasionally cost you an app until you allow
a domain by hand.

Both levels also subscribe to a **referral allowlist** — around 900 exceptions covering the
redirectors behind shopping, coupon and affiliate links, which broad tracker lists are
notorious for breaking. It is the piece that makes "does not break apps" mean something: its
entries override *every* other list, not just its own, so a tracker list and a working
checkout flow can coexist.

## What this does not do

It does not make you anonymous. A local firewall changes which servers your device talks to,
and nothing else:

- Your ISP or mobile carrier still sees every destination you connect to.
- Every site you visit still sees your real IP address.
- Browser fingerprinting — screen size, fonts, timezone, canvas — is untouched, and is how
  most commercial tracking actually identifies you.
- Anything you are signed in to knows exactly who you are regardless.

Blocking trackers reduces how much gets collected about you and by whom. That is worth doing,
and it is a different thing from anonymity. If you need to hide *where you are connecting
from*, that requires a real remote VPN or Tor, neither of which this app is.

## Limitations

Worth knowing before you rely on it:

- **Encrypted DNS hides lookups, and *Force filterable DNS* is the answer.** Since Android 9
  the Private DNS setting defaults to "Automatic", which quietly upgrades lookups to
  DNS-over-TLS on port 853 whenever the resolver supports it; Chrome and Firefox go further
  and use DNS-over-HTTPS to their own provider. A filter watching port 53 then sees nothing
  and blocks nothing, with no sign it has stopped working. The setting refuses port 853 and
  the known DoH bootstrap names so lookups fall back to a form that can be filtered. It stands
  down automatically if you pinned a specific Private DNS server, because there is no
  cleartext fallback in that mode and blocking it would leave you with no DNS at all. A client
  with hard-coded provider addresses still gets through.
- **Blocklists are third-party data.** They are maintained by other people and occasionally
  block something you wanted. The allowed-domains list overrides any of them.
- **MMS may not work while the tunnel is up.** Picture messages are often carried on a separate
  carrier APN that a VPN cannot reach, which is a routing problem rather than a blocking one.
  Ordinary SMS is unaffected: it travels on the cellular control channel and never touches IP.
- **Only one VPN can be active at a time.** Turning this on displaces any other VPN.
- **ICMP is dropped**, so `ping` will not work while the tunnel is up. Relaying it needs a raw
  socket, which a non-rooted app cannot open.
- **IP fragments are dropped** rather than reassembled.
- Turning on *Block IPv6* rebuilds the tunnel without IPv6 routes, so apps fall back to IPv4.
- The traffic log lives in memory only and is capped at 1000 entries. It is deliberately not
  written to disk — a persistent record of every connection a phone makes is a more sensitive
  artefact than this app is worth.

## Installing

You need a phone or tablet running **Android 10 (API 29) or newer**.

Option A needs nothing installed on your computer. Options B and C build it yourself.

### Option A — Download the APK built by CI (no build needed)

Every push is built automatically by GitHub Actions, and the resulting APK is attached to the
run.

1. Go to the [**Actions** tab](https://github.com/EndXSuffering/Shadowandroid/actions/workflows/build.yml).
2. Click the most recent run with a green ✅ tick.
3. Scroll to **Artifacts** at the bottom and download **shadow-firewall-apk**. You get a ZIP —
   unzip it to get `shadow-firewall-<commit>.apk`.
4. Copy the APK to your phone (email it, put it on a cloud drive, or use a USB cable), open it
   with a file manager, and tap install. Android will ask permission to *install unknown apps*
   from whichever app you opened it with — allow it.

Two things to know:

- **You need to be signed in to GitHub to download artifacts.** That is a GitHub rule, not this
  project's. If you are not signed in, the download link does nothing.
- The APK is signed with Android's standard **debug** key. It installs and runs normally, but
  it is not a release build, so Play Protect may show an extra "unsafe app blocked" warning —
  tap *More details → Install anyway*.

Then jump to [First run](#first-run).

### Option B — Android Studio

1. **Install Android Studio** from <https://developer.android.com/studio>. Accept the defaults
   in the setup wizard; it downloads the Android SDK for you.
2. **Get the code.** Either `git clone https://github.com/EndXSuffering/Shadowandroid.git`, or
   download the ZIP from GitHub and unpack it.
3. **Open it.** In Android Studio choose *File → Open* and select the `Shadowandroid` folder
   (the one containing `settings.gradle.kts`). Wait for "Gradle sync" to finish in the status
   bar — the first sync downloads dependencies and can take a few minutes.
4. **Turn on USB debugging on your phone.** Open *Settings → About phone* and tap **Build
   number** seven times to unlock developer mode, then go to *Settings → System → Developer
   options* and switch on **USB debugging**. (The exact menu names vary a little by
   manufacturer.)
5. **Plug the phone in.** Accept the "Allow USB debugging?" prompt on the phone. Your device
   should appear in the dropdown at the top of Android Studio.
6. **Press Run** (the green ▶ button). Android Studio builds the app, installs it, and launches
   it.

Then jump to [First run](#first-run).

### Option C — Command line

Use this if you would rather not install Android Studio, or you are building on a server.

**1. Install JDK 17**

```bash
# macOS
brew install openjdk@17

# Debian / Ubuntu
sudo apt install openjdk-17-jdk

# Check it worked
java -version    # should say 17.x
```

**2. Install the Android SDK command-line tools**

Download "Command line tools only" for your OS from
<https://developer.android.com/studio#command-line-tools-only>, then:

```bash
# Unpack into the layout the SDK expects
mkdir -p ~/android-sdk/cmdline-tools
unzip commandlinetools-*.zip -d ~/android-sdk/cmdline-tools
mv ~/android-sdk/cmdline-tools/cmdline-tools ~/android-sdk/cmdline-tools/latest

# Point the tooling at it (add these to ~/.bashrc or ~/.zshrc to make them stick)
export ANDROID_HOME=~/android-sdk
export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"

# Install the pieces this project needs and accept the licences
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"
sdkmanager --licenses
```

**3. Build the APK**

```bash
git clone https://github.com/EndXSuffering/Shadowandroid.git
cd Shadowandroid
./gradlew :app:assembleDebug
```

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`.

> If Gradle says it cannot find the SDK, create a `local.properties` file in the project root
> containing `sdk.dir=/absolute/path/to/android-sdk`.

**4. Install it on your phone**

With USB debugging enabled (steps 4–5 in Option B) and the phone plugged in:

```bash
adb devices                                             # confirm your phone is listed
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

No cable? Copy `app-debug.apk` to the phone (email, cloud drive, USB file transfer), open it
with a file manager, and approve the "install unknown apps" prompt when Android asks.

## First run

1. Open **Shadow Firewall**. You land on the **Apps** tab.
2. Tap **Start**. Android shows a **"Connection request"** dialog explaining that the app wants
   to set up a VPN — tap **OK**. This is Android's standard warning; it appears for any app that
   filters traffic. Nothing is sent to a remote server, the tunnel ends on your device.
3. Allow notifications if prompted. The ongoing notification is how the tunnel stays alive in
   the background, and it has a **Stop** button.
4. A small key icon appears in the status bar. That means the firewall is running.
5. Open any app, then come back to the **Traffic** tab to watch the connections appear.
6. To block something, either flip the Wi‑Fi or mobile switch next to an app on the **Apps**
   tab, or tap a row on the **Traffic** tab and choose **Block this app** / **Block this
   domain**. Rules apply to new connections immediately — no restart needed.

**To turn it off:** tap **Stop** in the app, or **Stop** on the notification. Your rules are
kept for next time.

**If something stops working**, the Traffic tab is the place to look: find the app, check
whether its connections say blocked, and flip its switch back off. *Settings → Reset all rules*
clears everything at once.

**To uninstall:** long-press the icon → *Uninstall*, same as any app. Android drops the VPN
configuration with it.

## Development

```bash
./gradlew :core:test             # unit tests for the packet and rule logic
./gradlew :app:assembleDebug     # debug APK
./gradlew :app:assembleRelease   # unsigned release APK — you must sign it yourself
```

Requires JDK 17 and the Android SDK (compileSdk 35). The release build has no signing config,
so `assembleRelease` produces `app-release-unsigned.apk`; the debug build is the one to use
unless you are setting up your own keystore.

### Continuous integration

`.github/workflows/build.yml` runs on every push and pull request: it runs the `core` unit
tests, builds the debug APK, and uploads it as the **shadow-firewall-apk** artifact (kept for
30 days). When a run fails it also uploads the Gradle test and lint reports, which is usually
enough to see what broke without reproducing it locally.

`gradle/actions/setup-gradle` validates the checked-in `gradle-wrapper.jar` against the set of
published Gradle wrapper checksums on every run, so a tampered wrapper fails the build. No
separate validation step is needed.

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
| `core/…/DomainHashSet.kt` | Sorted-hash domain set, the memory trick that makes big lists viable |
| `core/…/BlocklistParser.kt` | Reads hosts, AdGuard and plain-domain list formats |
| `app/…/rules/BlocklistRepository.kt` | Downloads, caches and loads the subscribed lists |
| `core/…/Dns.kt` | Query/response parsing and NXDOMAIN synthesis |
| `app/…/vpn/TunnelRelay.kt` | Reads the tun device, applies verdicts, owns the flow table |
| `app/…/vpn/TcpFlow.kt` | The userspace TCP state machine |
| `app/…/vpn/SelectorLoop.kt` | One NIO selector thread driving every relayed socket |
| `app/…/vpn/FirewallVpnService.kt` | Tunnel setup and service lifecycle |

## Testing status

`core/` has 94 unit tests covering checksums, IPv4 and IPv6 round trips, sequence-number
wrapping, RST generation, DNS parsing (including compression-pointer loops and truncated
input), suffix matching, cache expiry, blocklist parsing across all three formats, and the
hash-set index. Run them with `./gradlew :core:test`.

The parser was also run over the real lists it ships with — 464,000 rules across six files —
to check the extraction rate and confirm that none of twenty popular domains (google.com,
github.com, wikipedia.org and so on) came out blocked.

The `app/` module has no automated tests yet. The relay's behaviour under real traffic —
handshakes, flow control, teardown — has not been exercised against a device.
