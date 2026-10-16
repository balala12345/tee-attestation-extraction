#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android31-clang"
elif command -v aarch64-linux-android31-clang >/dev/null 2>&1; then
  CC="$(command -v aarch64-linux-android31-clang)"
else
  echo "STOP: set ANDROID_NDK_HOME or put aarch64-linux-android31-clang on PATH" >&2
  exit 2
fi

"$CC" \
  -std=c11 -O2 -fPIE -pie \
  -Wall -Wextra -Werror \
  "$HERE/xaga_keybox_readonly.c" \
  -ldl \
  -o "$HERE/xaga_keybox_readonly"

shasum -a 256 "$HERE/xaga_keybox_readonly" > "$HERE/xaga_keybox_readonly.sha256"
file "$HERE/xaga_keybox_readonly"
cat "$HERE/xaga_keybox_readonly.sha256"
