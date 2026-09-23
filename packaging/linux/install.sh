#!/usr/bin/env bash
# Install the YEMU bundle from this tarball.
#   ./install.sh            -> ~/.local/opt/yemu   (current user, no root)
#   sudo ./install.sh --system -> /opt/yemu        (all users)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--system" ]]; then
    PREFIX=/opt/yemu; BIN=/usr/local/bin; SHARE=/usr/local/share
else
    PREFIX="$HOME/.local/opt/yemu"; BIN="$HOME/.local/bin"; SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
fi

rm -rf "$PREFIX"
mkdir -p "$PREFIX" "$BIN" "$SHARE/applications" "$SHARE/icons/hicolor/256x256/apps"
cp -a "$HERE/YEMU/." "$PREFIX/"
ln -sf "$PREFIX/yemu" "$BIN/yemu"
ln -sf "$PREFIX/yemu-gui" "$BIN/yemu-gui"
cp "$HERE/io.github.ogshrug.YEMU.desktop" "$SHARE/applications/"
cp "$PREFIX/_internal/yemu/gui/assets/yemu.png" "$SHARE/icons/hicolor/256x256/apps/io.github.ogshrug.YEMU.png"
command -v update-desktop-database >/dev/null && update-desktop-database "$SHARE/applications" || true

echo "Installed YEMU to $PREFIX"
echo "  yemu doctor            # check QEMU/KVM/libvirt"
echo "  yemu vm create ubuntu-clean"
echo "  yemu-gui               # or find YEMU in your applications menu"
[[ ":$PATH:" == *":$BIN:"* ]] || echo "Note: add $BIN to your PATH."
