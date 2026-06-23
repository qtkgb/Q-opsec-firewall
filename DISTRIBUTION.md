# Installing & updating Q OpSec Firewall

A no-root, fully-local Android firewall. It's distributed privately (not on Google Play).
Pick **one** of the two methods below. Obtainium is recommended — it auto-updates when a new
version is released.

> **Requirements:** Android 10 or newer. You'll be asked to allow "Install unknown apps" for
> whichever app opens the file, and to approve a local VPN connection on first launch (the app
> uses Android's VpnService to filter traffic on-device — nothing is sent anywhere).

---

## Option A — Obtainium (recommended: auto-updates)

[Obtainium](https://github.com/ImranR98/Obtainium) installs apps straight from GitHub Releases
and keeps them updated.

1. **Install Obtainium**
   - Download the latest `Obtainium.apk` from
     <https://github.com/ImranR98/Obtainium/releases> and open it.
   - When prompted, allow your browser/Files app to "install unknown apps".

2. **Add the GitHub access token** *(needed because the firewall repo is private)*
   - Ask the maintainer for the **read-only access token** (a string starting with `github_pat_…`).
   - In Obtainium: **⚙ Settings → Source-specific settings → GitHub → Personal Access Token** →
     paste it → save.
   - You do **not** need your own GitHub account; the token is enough.

3. **Add the app**
   - Obtainium → **Add App** (the ➕).
   - Paste the repo URL:
     ```
     https://github.com/qtkgb/Q-opsec-firewall
     ```
   - Tap **Add**. Obtainium finds the latest release and its APK.
   - Tap **Install**, approve "install unknown apps" for Obtainium if asked.

4. **Updates**
   - Open Q OpSec Firewall in Obtainium and tap **Update** when one is available,
     or enable **Settings → Updates → background update checking** for automatic checks.
   - Updates install over the top and keep all your rules and history.

---

## Option B — Manual APK (one-off, no auto-update)

1. Download `Q-OpSec-Firewall.apk` from the latest release:
   <https://github.com/qtkgb/Q-opsec-firewall/releases/latest>
   *(private repo — you must be signed in to a GitHub account with access).*
2. Open the file on your phone and allow "install unknown apps" if prompted.
3. To update later, repeat with the newer APK — it installs over the top and keeps your data.

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

- The private repo means each phone needs a token. Recommended: create **one** *fine-grained*
  Personal Access Token scoped to **only** this repo with **Contents: Read-only**
  (github.com/settings/tokens), and share it with the circle for step A.2. Don't reuse your
  write token.
- Making the repo **public** removes the token step entirely (Obtainium just needs the URL).
- Cut a new release with `./release.sh` after bumping **versionCode and versionName**
  (Obtainium keys off the release tag, so versionName must change each release).
