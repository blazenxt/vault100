#!/usr/bin/env bash
# Vault100 Pocket Annex — one-command APK assembly. No Gradle, no IDE.
#
# Needs on PATH or via env:
#   JAVA_HOME            JDK 17+          (default: /home/user/tools/jdk-17*)
#   ANDROID_HOME         Android SDK root (default: /home/user/android-sdk)
#                         with platforms;android-34 + build-tools;34.0.0
#   V100_KEYSTORE        signing keystore (default: /home/user/vault100-keys/vault100-release.keystore)
#   V100_STOREPASS_FILE  file holding the keystore password
#                         (default: /home/user/vault100-keys/storepass.txt)
#
# Usage:  ./build.sh            → dist/Vault100-<version>.apk (signed, aligned)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$ROOT/../web" && pwd)"
SDK="${ANDROID_HOME:-/home/user/android-sdk}"
BT_DIR="$SDK/build-tools/34.0.0"
PLATFORM_JAR="$SDK/platforms/android-34/android.jar"
KEYSTORE="${V100_KEYSTORE:-/home/user/vault100-keys/vault100-release.keystore}"
PASS_FILE="${V100_STOREPASS_FILE:-/home/user/vault100-keys/storepass.txt}"

if [ -z "${JAVA_HOME:-}" ]; then
  JAVA_HOME="$(ls -d /home/user/tools/jdk-17* 2>/dev/null | head -1 || true)"
fi
export PATH="${JAVA_HOME:+$JAVA_HOME/bin}:$PATH"

VERSION="$(sed -n 's/.*android:versionName="\([^"]*\)".*/\1/p' "$ROOT/AndroidManifest.xml")"
GEN="$ROOT/gen"; OBJ="$ROOT/obj"; ASSETS="$ROOT/assets"; DIST="$ROOT/dist"

echo "· bundling the bureau (web/ → assets/webroot)…"
rm -rf "$ASSETS/webroot"
mkdir -p "$ASSETS/webroot"
cp -a "$WEB/." "$ASSETS/webroot/"
rm -f "$ASSETS/webroot/server.mjs" "$ASSETS/webroot/DEPLOY.md" \
      "$ASSETS/webroot/og-cover.jpg" "$ASSETS/webroot/sitemap.xml" \
      "$ASSETS/webroot/robots.txt"

echo "· compiling resources…"
rm -rf "$GEN" "$OBJ"; mkdir -p "$GEN" "$OBJ"
"$BT_DIR/aapt2" compile --dir "$ROOT/res" -o "$GEN/res.zip"
"$BT_DIR/aapt2" link -o "$GEN/unsigned.apk" \
  -I "$PLATFORM_JAR" \
  --manifest "$ROOT/AndroidManifest.xml" \
  -A "$ASSETS" \
  --java "$GEN/java" \
  "$GEN/res.zip" --auto-add-overlay

echo "· compiling the shell (javac)…"
find "$GEN/java" "$ROOT/java" -name '*.java' > "$GEN/sources.txt"
javac -source 8 -target 8 -encoding UTF-8 -classpath "$PLATFORM_JAR" \
  -d "$OBJ" @"$GEN/sources.txt" 2> >(grep -v "bootstrap class path\|deprecat" >&2 || true)

echo "· dexing (d8)…"
mkdir -p "$GEN/dex"
"$BT_DIR/d8" --release --min-api 24 --output "$GEN/dex" --lib "$PLATFORM_JAR" \
  $(find "$OBJ" -name '*.class')

echo "· packing + aligning…"
(cd "$GEN/dex" && zip -q -j -0 ../unsigned.apk classes.dex)
"$BT_DIR/zipalign" -f -p 4 "$GEN/unsigned.apk" "$GEN/aligned.apk"

echo "· sealing the APK (apksigner)…"
mkdir -p "$DIST"
# (no --key-pass: apksigner reuses the keystore password by default, and its
#  file: password reader chokes on a second read of the same file — EOF)
"$BT_DIR/apksigner" sign \
  --ks "$KEYSTORE" --ks-key-alias vault100 \
  --ks-pass "file:$PASS_FILE" \
  --out "$DIST/Vault100-${VERSION}.apk" "$GEN/aligned.apk"

echo
echo "· verification:"
"$BT_DIR/apksigner" verify --print-certs "$DIST/Vault100-${VERSION}.apk" | sed 's/^/  /'
echo
sha256sum "$DIST/Vault100-${VERSION}.apk" | tee "$DIST/Vault100-${VERSION}.apk.sha256"
ls -la "$DIST/Vault100-${VERSION}.apk"
echo
echo "sealed. sideload with:  adb install $DIST/Vault100-${VERSION}.apk"
