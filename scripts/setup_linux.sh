#!/usr/bin/env bash
# Set up YEMU on Debian/Ubuntu, including inside WSL2 on Windows.
#   bash scripts/setup_linux.sh            # full install (libvirt + desktop app + CLI)
#   bash scripts/setup_linux.sh --qemu-only  # skip libvirt; standalone QEMU backend + desktop app
set -euo pipefail

QEMU_ONLY=0
[[ "${1:-}" == "--qemu-only" ]] && QEMU_ONLY=1

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

log() { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

IS_WSL=0
grep -qi microsoft /proc/version 2>/dev/null && IS_WSL=1

if [[ $IS_WSL == 1 ]]; then
    log "Running inside WSL2"
    if [[ ! -d /run/systemd/system ]]; then
        warn "systemd is not running. libvirtd needs it. Enabling it in /etc/wsl.conf..."
        if ! grep -q "systemd=true" /etc/wsl.conf 2>/dev/null; then
            printf '[boot]\nsystemd=true\n' | sudo tee -a /etc/wsl.conf >/dev/null
        fi
        warn "Run 'wsl --shutdown' from Windows, reopen this distro, and re-run this script."
        [[ $QEMU_ONLY == 1 ]] || exit 1
    fi
    if [[ ! -e /dev/kvm ]]; then
        warn "/dev/kvm is missing: nested virtualization is off. Add this to %UserProfile%\\.wslconfig on Windows:"
        warn "    [wsl2]"
        warn "    nestedVirtualization=true"
        warn "then run 'wsl --shutdown'. YEMU still works without it, but VMs fall back to slow TCG emulation."
    fi
fi

# libegl1/libxkbcommon/libxcb-cursor0: runtime libraries for the Qt desktop app
PKGS=(qemu-system-x86 qemu-utils python3-venv python3-pip yara strace libegl1 libxkbcommon-x11-0 libxcb-cursor0)
if [[ $QEMU_ONLY == 0 ]]; then
    PKGS+=(qemu-kvm libvirt-daemon-system libvirt-clients virt-manager virt-viewer libguestfs-tools
           genisoimage python3-libvirt tcpdump)
fi
log "Installing packages: ${PKGS[*]}"
sudo apt-get update
sudo apt-get install -y "${PKGS[@]}"

if [[ $QEMU_ONLY == 0 ]]; then
    sudo systemctl enable --now libvirtd || warn "Could not start libvirtd"
    if ! id -nG "$USER" | grep -qw libvirt || ! id -nG "$USER" | grep -qw kvm; then
        log "Adding $USER to the libvirt and kvm groups (log out and back in afterwards)"
        sudo usermod -aG libvirt,kvm "$USER"
    fi
elif [[ -e /dev/kvm ]] && ! id -nG "$USER" | grep -qw kvm; then
    sudo usermod -aG kvm "$USER"
fi

if [[ ! -d .venv ]]; then
    log "Creating .venv (with system site-packages, for the distro's libvirt bindings)"
    python3 -m venv .venv --system-site-packages
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip >/dev/null
if [[ $QEMU_ONLY == 0 ]]; then
    pip install -e ".[linux,gui,dev]"
else
    pip install -e ".[gui,dev]"
fi

log "Running yemu doctor"
yemu doctor || true
echo
log "Done. Activate with: source .venv/bin/activate"
echo "    yemu vm create ubuntu-clean   # build an isolated analysis VM"
echo "    yemu gui                      # desktop app (needs a display; WSLg works inside WSL2)"
