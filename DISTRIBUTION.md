# Installing & updating Q OpSec Firewall

A no-root, fully-local Android firewall. It's distributed privately (not on Google Play).

> **Requirements:** Android 10 or newer. You'll be asked to allow "Install unknown apps" for
> whichever app opens the file, and to approve a local VPN connection on first launch (the app
> uses Android's VpnService to filter traffic on-device — nothing is sent anywhere).

---

## Updating (once you're on 1.1.1 or newer): built-in updater

From version **1.1.1** onward the app updates **itself** — no second app, no account:

- It checks GitHub for a new release **once a day** in the background and notifies you.
- Or check any time: **Settings → "Check for updates daily" → Check now**. When a newer version
  exists you'll see an **Update available** card → tap **Download & install**.
- Android shows its normal install screen to confirm (nothing installs silently). The update
  installs over the top and keeps all your rules, snapshots, and history.

You only need one of the methods below for the **first** install. After that the built-in
updater handles everything.

---

## First install — Option A: Manual APK (simplest)

1. Download `Q-OpSec-Firewall.apk` from the latest release:
   <https://github.com/qtkgb/Q-opsec-firewall/releases/latest>
2. Open the file on your phone and allow "install unknown apps" if prompted.
3. Launch it and approve the VPN prompt. Done — future updates are automatic (see above).

## First install — Option B: Obtainium

[Obtainium](https://github.com/ImranR98/Obtainium) installs apps straight from GitHub Releases
and keeps them updated. Useful if you'd rather manage updates from one place, but with the
built-in updater it's optional.

1. **Install Obtainium** — download the latest `Obtainium.apk` from
   <https://github.com/ImranR98/Obtainium/releases> and open it (allow "install unknown apps").
2. **Add the app** — Obtainium → **Add App** (➕) → paste the repo URL:
   ```
   https://github.com/qtkgb/Q-opsec-firewall
   ```
   Tap **Add**. The repo is **public**, so no token or GitHub account is needed.
3. **Install** — tap **Install** and approve "install unknown apps" for Obtainium if asked.

---

## Notes

- **Updates keep your data.** Every release is signed with the same key, so a new version
  installs over the old one without losing your rules, snapshots, or connection history.
- **First-time only:** if you previously installed a *test/debug* build, uninstall it first
  (debug and release builds use different signing keys). Normal release-to-release updates
  never need this.
- **First launch:** approve the VPN prompt. The app is a local firewall — it runs entirely on
  your device, with no account, no cloud, and no data collection.

## For the maintainer

- The repo is **public**, so neither Obtainium nor the in-app updater needs a token — they read
  releases anonymously. (The in-app updater embeds no secret; that's why it requires public
  releases.)
- Cut a new release with `./release.sh` after bumping **versionCode and versionName**. The
  in-app updater and Obtainium both key off the release **tag** (versionName), so versionName
  must change every release — not just versionCode.
