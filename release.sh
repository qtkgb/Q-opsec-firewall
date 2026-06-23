#!/usr/bin/env bash
# Publish a GitHub Release with the signed release APK, so phones running Obtainium
# auto-update from it. The GitHub token is read from the git credential helper
# (osxkeychain) at run time — it is never stored in or printed by this script.
#
# Usage:
#   1. bump versionCode + versionName in app/build.gradle.kts
#   2. build + commit + push, then run:  ./release.sh
# It tags the current pushed HEAD as v<versionName> and attaches the APK.
set -euo pipefail
cd "$(dirname "$0")"

REPO="qtkgb/Q-opsec-firewall"
APK="app/build/outputs/apk/release/Q-OpSec-Firewall.apk"
VER=$(grep -oE 'versionName = "[^"]+"' app/build.gradle.kts | head -1 | cut -d'"' -f2)
TAG="v$VER"

[ -f "$APK" ] || { echo "ERROR: $APK not found — run an assembleRelease first."; exit 1; }

TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')
[ -n "$TOKEN" ] || { echo "ERROR: no GitHub token in the credential helper. Do a 'git push' once first."; exit 1; }

api()    { curl -sS -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

# Already released? (idempotent)
if api "https://api.github.com/repos/$REPO/releases/tags/$TAG" | grep -q '"id":'; then
  echo "Release $TAG already exists — bump the version first, or delete it on GitHub."; exit 1
fi

echo "Creating release $TAG ..."
RESP=$(api -X POST "https://api.github.com/repos/$REPO/releases" \
  -d "{\"tag_name\":\"$TAG\",\"name\":\"$TAG\",\"body\":\"Q OpSec Firewall $TAG — signed APK below. Updates over the top (same signing key).\"}")
ID=$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')
[ -n "$ID" ] || { echo "ERROR: release create failed:"; printf '%s\n' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("message","?"))'; exit 1; }

echo "Uploading APK ..."
CODE=$(curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.android.package-archive" \
  "https://uploads.github.com/repos/$REPO/releases/$ID/assets?name=Q-OpSec-Firewall.apk" \
  --data-binary @"$APK" -o /dev/null -w '%{http_code}')
[ "$CODE" = "201" ] || { echo "ERROR: asset upload returned HTTP $CODE"; exit 1; }

echo "Done: https://github.com/$REPO/releases/tag/$TAG"
