# Shadow Firewall

[![Build APK](https://github.com/EndXSuffering/Shadowandroid/actions/workflows/build.yml/badge.svg)](https://github.com/EndXSuffering/Shadowandroid/actions/workflows/build.yml)

An Android app that shows you every connection your apps make, and blocks the ones you don't
want. No root required.

- **See traffic** — a live log of every connection, attributed to the app that made it, with
  the hostname, port, verdict and byte counts.
- **Block per app** — separate Wi-Fi and mobile-data switches for each installed app.
- **Block per domain** — a suffix-matched blocklist (`doubleclick.net` also covers
  `ad.doubleclick.net`), with an allowlist that overrides it.
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
