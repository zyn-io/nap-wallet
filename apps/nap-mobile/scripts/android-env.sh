# Source me: `. scripts/android-env.sh` — the environment the Android build needs.
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
REAL_NDK="$ANDROID_HOME/ndk/27.1.12297006"
# A short target dir keeps the linker's argument list small.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/napm}"

# This machine's NDK has two broken arm64 wrappers (they call themselves). If
# so, build against a shadow NDK: links to the real one, those two restored.
W="$REAL_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
if grep -q 'exec "$TOOLCHAIN/bin/aarch64-linux-android24-clang"' "$W" 2>/dev/null; then
  S=/tmp/ndk27-shadow
  if [ ! -e "$S/source.properties" ]; then
    mkdir -p "$S/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    for f in "$REAL_NDK"/*; do [ "$(basename "$f")" = toolchains ] || ln -sf "$f" "$S/"; done
    for f in "$REAL_NDK"/toolchains/*; do [ "$(basename "$f")" = llvm ] || ln -sf "$f" "$S/toolchains/"; done
    for f in "$REAL_NDK"/toolchains/llvm/*; do [ "$(basename "$f")" = prebuilt ] || ln -sf "$f" "$S/toolchains/llvm/"; done
    P="$REAL_NDK/toolchains/llvm/prebuilt/darwin-x86_64"
    for f in "$P"/*; do [ "$(basename "$f")" = bin ] || ln -sf "$f" "$S/toolchains/llvm/prebuilt/darwin-x86_64/"; done
    for f in "$P"/bin/*; do ln -sf "$f" "$S/toolchains/llvm/prebuilt/darwin-x86_64/bin/"; done
    for w in clang clang++; do
      rm -f "$S/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-$w"
      printf '#!/usr/bin/env bash\nbin_dir=`dirname "$0"`\nif [ "$1" != "-cc1" ]; then\n    "$bin_dir/%s" --target=aarch64-linux-android24 "$@"\nelse\n    "$bin_dir/%s" "$@"\nfi\n' "$w" "$w" > "$S/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-$w"
      chmod +x "$S/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-$w"
    done
  fi
  export NDK_HOME="$S"
else
  export NDK_HOME="$REAL_NDK"
fi
echo "Android build env: NDK_HOME=$NDK_HOME"
