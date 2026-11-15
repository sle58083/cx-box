#!/bin/bash
# 构建 cx-box 发布包：cx-box-linux-<arch>.tar.gz
# 包内布局（install.sh 按此布局解压安装）：
#   cx-box/cx-box         Go 二进制
#   cx-box/cx-box.sh      管理脚本（安装到 /usr/bin/cx-box）
#   cx-box/cx-box.service systemd 单元
#
# 用法：scripts/build-release.sh [arch] [version]
#   arch: amd64 | arm64 | 386 | armv7 | armv6 | armv5 | s390x（默认 amd64）
#   version: 仅用于打印，可选
set -euo pipefail

cd "$(dirname "$0")/.."

ARCH="${1:-amd64}"
VERSION="${2:-dev}"

GOARCH="$ARCH"
GOARM=""
case "$ARCH" in
amd64 | arm64 | 386 | s390x) ;;
armv7) GOARCH="arm"; GOARM="7" ;;
armv6) GOARCH="arm"; GOARM="6" ;;
armv5) GOARCH="arm"; GOARM="5" ;;
*) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

OUT="dist"
PKG="${OUT}/cx-box"
rm -rf "$PKG"
mkdir -p "$PKG"

echo "building cx-box for linux/${ARCH} (version ${VERSION})..."
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
    go build -trimpath -ldflags "-s -w" -o "${PKG}/cx-box" ./cmd/cx-box

cp cx-box.sh cx-box.service "$PKG/"
chmod +x "${PKG}/cx-box" "${PKG}/cx-box.sh"

tar -czf "${OUT}/cx-box-linux-${ARCH}.tar.gz" -C "$OUT" cx-box
echo "done: ${OUT}/cx-box-linux-${ARCH}.tar.gz"
tar -tzf "${OUT}/cx-box-linux-${ARCH}.tar.gz"
