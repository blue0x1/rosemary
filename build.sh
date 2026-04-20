#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="$SCRIPT_DIR/dist"

# Usage: ./build.sh [server|agent|all] [linux|windows|darwin|freebsd|openbsd|all] [amd64|arm64|arm|386|all]
TARGET="${1:-all}"   # server | agent | all
OS="${2:-all}"       # linux | windows | darwin | freebsd | openbsd | all
ARCH="${3:-all}"     # amd64 | arm64 | arm | 386 | all

MIN_SERVER_SIZE=8000000   # 8 MB
MIN_AGENT_SIZE=4000000    # 4 MB

mkdir -p "$DIST"

build() {
    local name="$1"
    local goos="$2"
    local goarch="$3"
    local src="$SCRIPT_DIR/$name"
    local out="$DIST/${name}-${goos}-${goarch}"
    [ "$goos" = "windows" ] && out="${out}.exe"

    local extra_env=""
    [ "$goarch" = "arm" ] && extra_env="GOARM=7"

    (cd "$src" && \
        env GOTOOLCHAIN=auto \
            CGO_ENABLED=0 \
            GOOS="$goos" \
            GOARCH="$goarch" \
            $extra_env \
        go build -trimpath -ldflags="-s -w" -o "$out" .) || {
        echo "    FAILED: $out"
        return 1
    }

    local size
    size=$(stat -c %s "$out" 2>/dev/null || stat -f %z "$out")
    local min_size
    [ "$name" = "server" ] && min_size=$MIN_SERVER_SIZE || min_size=$MIN_AGENT_SIZE

    if [ "$size" -lt "$min_size" ]; then
        echo "    WARNING: $out is suspiciously small ($((size / 1024 / 1024))M) — may be incomplete"
    else
        echo "    $out ($((size / 1024 / 1024))M)"
    fi
}

should_build_target() { [ "$TARGET" = "all" ] || [ "$TARGET" = "$1" ]; }
should_build_os()     { [ "$OS"     = "all" ] || [ "$OS"     = "$1" ]; }
should_build_arch()   { [ "$ARCH"   = "all" ] || [ "$ARCH"   = "$1" ]; }

declare -A OS_ARCHS
OS_ARCHS[linux]="amd64 arm64 arm 386"
OS_ARCHS[windows]="amd64 arm64 386"
OS_ARCHS[darwin]="amd64 arm64"
OS_ARCHS[freebsd]="amd64 arm64 arm 386"
OS_ARCHS[openbsd]="amd64 arm64 arm 386"

for name in server agent; do
    should_build_target "$name" || continue
    echo "[*] Building $name..."
    for goos in linux windows darwin freebsd openbsd; do
        should_build_os "$goos" || continue
        for goarch in ${OS_ARCHS[$goos]}; do
            should_build_arch "$goarch" || continue
            build "$name" "$goos" "$goarch"
        done
    done
done

echo "[+] Done. Binaries in dist/:"
ls -lh "$DIST"
