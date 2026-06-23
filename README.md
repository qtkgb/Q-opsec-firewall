# Q opsec firewall — Android, v1 (Phase 0: capture skeleton)

A local, zero-egress firewall. **Phase 0** proves the foundation: become the phone's
VPN endpoint, capture **every** outbound connection, and show it live. Nothing is
forwarded yet and **nothing leaves the device** — this build has no INTERNET permission.

## What it does
- Requests VPN consent (`VpnService.prepare`) and runs a foreground service.
- Establishes a TUN with a catch-all route (`0.0.0.0/0` + `::/0`) so all traffic is captured.
- Reads each IP packet, parses the IPv4/IPv6 5-tuple, and lists unique destinations live.
- Drops every packet (no forwarding) — see the caveat below.

## ⚠️ Phase 0 caveat — traffic is paused while running
Because there is no forwarding yet, **while capture is ON the device has no working
internet** (packets are observed then dropped). Tap **Stop** (or revoke the VPN in
Settings) to restore connectivity. Forwarding via protected sockets arrives in **Phase 1**.

## Build & run
This project has no Gradle wrapper JAR checked in. Either:

**Android Studio (easiest):** open the `v1/` folder; it generates the wrapper and syncs.
Then Run on a device/emulator (API 29+).

**CLI:** generate the wrapper once, then build:
```bash
cd "Q opsec firewall/android/v1"
gradle wrapper --gradle-version 8.9   # requires a local Gradle; creates ./gradlew
./gradlew assembleDebug
./gradlew installDebug                 # to a connected device (adb)
```

Then on the device: launch **Q opsec firewall** → **Start capture** → approve the VPN
prompt → watch connections appear. **Stop** when done to get internet back.

## Layout
```
app/src/main/
  AndroidManifest.xml                 # perms, VpnService (specialUse FGS), no INTERNET
  java/com/qopsec/firewall/
    MainActivity.kt                   # consent + start/stop, Compose host
    ui/CaptureScreen.kt               # live list, Start/Stop/Clear
    ui/Theme.kt
    vpn/VpnFirewallService.kt         # TUN establish + read loop (drops packets)
    vpn/PacketParser.kt               # IPv4/IPv6 5-tuple parser (moves to Rust later)
    vpn/ConnectionEvent.kt            # observed-flow model
    vpn/CaptureLog.kt                 # in-memory StateFlow sink (UI observes)
```

## Config (matches the agreed spec)
- `minSdk 29` (Android 10 — floor for `getConnectionOwnerUid`, used in Phase 1)
- `targetSdk / compileSdk 35`
- Components explicitly `exported` true only for the launcher; service `exported=false`.

## Security notes (Phase 0)
- No INTERNET permission, no analytics/crash SDKs, no network calls — verifiably local.
- `onRevoke()` stops cleanly so the tunnel can't silently linger.
- The packet parser is deliberately small; in the production build this logic moves into
  the memory-safe **Rust core** (report finding N-1: don't parse hostile packets unsafely).

## Next — Phase 1
Resolve the owning app (`getConnectionOwnerUid`), sniff DNS for hostnames, and forward
allowed flows through `protect()`-ed sockets so the phone works normally (allow-by-default).
