#!/usr/bin/env bash
# Build the Virus Vigil Android APK on this laptop WITHOUT Windows Developer Mode.
#
# Why this exists: `tauri android build` compiles Rust fine, then tries to SYMLINK the .so
# into gen/android/app/src/main/jniLibs, and Windows refuses symlinks outside Developer
# Mode ("Creation symbolic link is not allowed for this system"). So: let Tauri compile
# (its failure is only that last link), COPY the .so ourselves, then run Gradle with its
# own Rust step skipped (that step calls Tauri again and would try the same link).
#
# Must run from the REAL path, never a subst drive: Tauri compares a canonicalised path
# against a plain one and panics "AssetDirOutsideOfAppRoot". So a subst drive is resolved below.
#
# Usage: build-android.sh [x86_64|aarch64] [debug|release]   -> prints the APK path, exit 0
set -uo pipefail
ABI="${1:-x86_64}"; MODE="${2:-debug}"; KEYED="${3:-}"
APP="${VV_APP:-$(cd "$(dirname "$0")" && pwd -W)}"
# If this folder sits on a subst drive (e.g. R: -> C:\Something), swap the drive for its real target.
SUBST_REAL=$(subst 2>/dev/null | tr -d '\r' | awk -v d="${APP:0:2}" 'toupper(substr($0,1,2))==toupper(d) {sub(/^.*=> /,""); print}')
[ -n "$SUBST_REAL" ] && APP="$(echo "$SUBST_REAL" | tr '\\' '/')${APP:2}"
LOG="${VV_BUILD_LOG:-$TEMP/vv-android-build.log}"
# Your own install wins; these are only the fallbacks for the laptop this was built on.
export ANDROID_HOME="${ANDROID_HOME:-D:\\dev\\android-sdk}"
export NDK_HOME="${NDK_HOME:-D:\\dev\\android-sdk\\ndk\\29.0.14206865}"
export JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Java\\jdk-21}"
# The online AI's key (Groq). Anyone holding the APK can pull a baked key out and spend on his
# account, so since 29 Sep 2026 (LEGAL-CHECK.md R2, his tap "All free fixes now") the DEFAULT build
# carries NO key; only `build-android.sh <abi> <mode> personal` bakes his GROQ_API_KEY in, for his
# own phone. No key = the app says the online AI is "not set up".
if [ "$KEYED" = "personal" ]; then
  export VV_GROQ_KEY="${GROQ_API_KEY:-}"
  # abuse.ch Auth-Key for the known-malware lists (keyless answers 410 since Oct 2026).
  export VV_MB_KEY="${ABUSE_CH_AUTH_KEY:-}"
  [ -n "$VV_MB_KEY" ] || echo "WARNING: ABUSE_CH_AUTH_KEY is empty - the phone will get no known-malware list"
  [ -n "$VV_GROQ_KEY" ] || echo "WARNING: GROQ_API_KEY is empty - the online AI will say it is not set up"
  echo "PERSONAL build: his Groq key goes IN - never share this APK"
elif [ -n "$KEYED" ]; then
  echo "third argument must be 'personal' or nothing, got '$KEYED'"; exit 2
else
  export VV_GROQ_KEY=""
  export VV_MB_KEY=""
  echo "SHAREABLE build: no AI key inside"
fi

case "$ABI" in
  x86_64)  TRIPLE=x86_64-linux-android;  JNI=x86_64;     GTASK=X86_64 ;;
  aarch64) TRIPLE=aarch64-linux-android; JNI=arm64-v8a;  GTASK=Arm64 ;;
  *) echo "unknown ABI $ABI"; exit 2 ;;
esac
case "$MODE" in
  debug)   FLAG=--debug; GMODE=Debug ;;
  release) FLAG="";      GMODE=Release ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac

cd "$APP" || exit 2
SO="src-tauri/target/$TRIPLE/$MODE/libvirus_vigil_lib.so"
START=$(date +%s)

# 1. Tauri: codegen + Rust compile. Expected to fail ONLY at the symlink step.
npx tauri android build $FLAG --apk --target "$ABI" --ci > "$LOG" 2>&1
rc=$?
if [ $rc -ne 0 ] && ! grep -q "symbolic link" "$LOG"; then
  echo "tauri build failed for a reason other than the symlink - see $LOG"; tail -30 "$LOG"; exit 1
fi
# The .so must be from THIS run, not a leftover.
if [ ! -f "$SO" ] || [ "$(stat -c %Y "$SO")" -lt "$START" ]; then
  echo "no fresh $SO from this run - see $LOG"; tail -30 "$LOG"; exit 1
fi

# The key must really be inside a personal library, and NO key-shaped string inside any other
# (checked without printing it).
if [ -n "$VV_GROQ_KEY" ] && ! grep -qaF "$VV_GROQ_KEY" "$SO"; then
  echo "the online AI key is NOT in $SO - cargo did not rebuild with VV_GROQ_KEY"; exit 1
fi
if [ -n "$VV_MB_KEY" ] && ! grep -qaF "$VV_MB_KEY" "$SO"; then
  echo "the abuse.ch key is NOT in $SO - cargo did not rebuild with VV_MB_KEY"; exit 1
fi
if [ -z "$VV_MB_KEY" ] && [ -n "${ABUSE_CH_AUTH_KEY:-}" ] && grep -qaF "$ABUSE_CH_AUTH_KEY" "$SO"; then
  echo "REFUSED: the abuse.ch key is inside $SO although this build is shareable"; exit 1
fi
if [ -z "$VV_GROQ_KEY" ] && grep -qaE 'gsk_[A-Za-z0-9]{20}' "$SO"; then
  echo "REFUSED: a Groq key is inside $SO although this build is shareable"; exit 1
fi

# 2. Copy (not link) the library where Gradle packs it.
DEST="src-tauri/gen/android/app/src/main/jniLibs/$JNI"
mkdir -p "$DEST" && rm -f "$DEST/libvirus_vigil_lib.so" && cp "$SO" "$DEST/" || exit 1
cmp -s "$SO" "$DEST/libvirus_vigil_lib.so" || { echo "copy differs"; exit 1; }

# 3. Gradle, skipping its Rust step.
cd src-tauri/gen/android || exit 2
./gradlew.bat "assemble${GTASK}${GMODE}" -x "rustBuild${GTASK}${GMODE}" >> "$LOG" 2>&1 || { echo "gradle failed - see $LOG"; tail -30 "$LOG"; exit 1; }
APK=$(find app/build/outputs/apk -name "*.apk" -newer "$APP/$SO" | head -1)
[ -n "$APK" ] || { echo "gradle ran but no new APK"; exit 1; }
echo "$APP/src-tauri/gen/android/$APK"
