#!/usr/bin/env bash
set -euo pipefail

VM_NAME=""
DISTRO="ubuntu"
RAM="2048"
CPU="2"
DISK_SIZE="20"
DOWNLOAD_DIR=""
NETWORK_NAME="malware-analysis"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="/tmp/gpcssi-$USER"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$DATA_DIR}"
DISK_DIR="$DATA_DIR"
LOG_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup() {
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
}
trap cleanup EXIT

check_deps() {
    local missing=()
    local pkgs=()

    # Map commands to packages
    declare -A cmd_to_pkg=(
        ["zenity"]="zenity"
        ["wget"]="wget"
        ["curl"]="curl"
        ["qemu-img"]="qemu-utils"
        ["virsh"]="libvirt-clients"
        ["genisoimage"]="genisoimage"
        ["virt-viewer"]="virt-viewer"
        ["yara"]="yara"
    )

    for cmd in "${!cmd_to_pkg[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
            pkgs+=("${cmd_to_pkg[$cmd]}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing[*]}"
        if zenity --question --title="Missing Dependencies" \
           --text="The following packages are missing: ${pkgs[*]}\n\nWould you like to install them now? (Requires sudo)" \
           --width=400 2>/dev/null; then

            log "Installing missing packages: ${pkgs[*]}..."
            # Use zenity to run sudo command and show progress
            if pkexec apt-get update && pkexec apt-get install -y "${pkgs[@]}"; then
                log "Dependencies installed successfully."
            else
                error "Failed to install dependencies."
                return 1
            fi
        else
            error "Dependencies not installed. Please install manually: sudo apt install ${pkgs[*]}"
            return 1
        fi
    fi
}

check_libvirt() {
    if ! virsh list --all &>/dev/null; then
        error "Cannot connect to libvirt. Is libvirtd running?"
        error "Try: sudo systemctl start libvirtd"
        return 1
    fi
}

get_input_zenity() {
    if ! command -v zenity &>/dev/null; then
        error "zenity not found. Install with: sudo apt install zenity"
        return 1
    fi

    local form
    form=$(zenity --forms \
        --title="VM Preparation Tool" \
        --text="Configure the new virtual machine" \
        --add-entry="VM Name" \
        --add-combo="Distribution" \
        --combo-values="ubuntu|debian|windows" \
        --add-entry="RAM (MiB)" \
        --add-entry="CPU Cores" \
        --add-entry="Disk Size (GiB)" \
        --forms-date-format="%Y-%m-%d" \
        2>/dev/null)

    [[ -z "$form" ]] && return 1

    IFS='|' read -r VM_NAME DISTRO RAM CPU DISK_SIZE <<< "$form"

    VM_NAME="${VM_NAME:-ubuntu-clean}"
    DISTRO="${DISTRO:-ubuntu}"
    RAM="${RAM:-2048}"
    CPU="${CPU:-2}"
    DISK_SIZE="${DISK_SIZE:-20}"
}

show_progress() {
    local msg="$1" pct="$2"
    echo "# $msg"
    echo "$pct"
}

ensure_network() {
    log "Ensuring isolated network '$NETWORK_NAME'..."
    if virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "Network '$NETWORK_NAME' already exists."
        # Destroy and redefine to ensure NAT is enabled
        virsh net-destroy "$NETWORK_NAME" &>/dev/null || true
        virsh net-undefine "$NETWORK_NAME" &>/dev/null || true
    fi

    log "Creating network '$NETWORK_NAME' with NAT..."
    local xml
    xml=$(cat <<EOF
<network>
  <name>$NETWORK_NAME</name>
  <forward mode='nat'/>
  <bridge name='virbr-malware' stp='on' delay='0'/>
  <ip address='192.168.100.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.100.10' end='192.168.100.100'/>
    </dhcp>
  </ip>
</network>
EOF
)
    virsh net-define /dev/stdin <<<"$xml" || return 1
    virsh net-autostart "$NETWORK_NAME" || true
    virsh net-start "$NETWORK_NAME" || true
    log "Network '$NETWORK_NAME' created."
}

download_file() {
    local url="$1" target="$2"
    if [[ -f "$target" ]]; then
        log "File already exists: $(basename "$target")"
        return 0
    fi
    log "Downloading $(basename "$target")..."
    mkdir -p "$(dirname "$target")"
    if command -v wget &>/dev/null; then
        wget -q --show-progress "$url" -O "$target" || return 1
    else
        curl -L -o "$target" "$url" || return 1
    fi
}

create_cloud_init_iso() {
    local vm_name="$1" tmpdir="$2" iso_path="$3"
    local user_data="$tmpdir/user-data"
    local meta_data="$tmpdir/meta-data"

    cat > "$user_data" << 'EOF'
#cloud-config
package_update: true
package_upgrade: true
packages:
  - qemu-guest-agent
  - strace
  - tcpdump
  - curl
password: analysis-password
chpasswd:
  expire: false
ssh_pwauth: true
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
EOF

    cat > "$meta_data" << EOF
instance-id: $vm_name
local-hostname: $vm_name
EOF

    genisoimage -output "$iso_path" -volid cidata -joliet -rock "$user_data" "$meta_data" &>/dev/null || return 1
    chmod 644 "$iso_path"
}

create_disk() {
    local disk_path="$1" size="$2" backing="$3"
    mkdir -p "$(dirname "$disk_path")"

    local cmd=(qemu-img create -f qcow2)
    if [[ -n "$backing" ]]; then
        cmd+=(-b "$backing" -F qcow2 "$disk_path" "${size}G")
    else
        cmd+=("$disk_path" "${size}G")
    fi

    if ! "${cmd[@]}" &>/dev/null; then
        warn "Could not create disk at $disk_path, retrying in $DATA_DIR..."
        disk_path="$DATA_DIR/$(basename "$disk_path")"
        mkdir -p "$DATA_DIR"
        cmd=()
        if [[ -n "$backing" ]]; then
            cmd=(qemu-img create -f qcow2 -b "$backing" -F qcow2 "$disk_path" "${size}G")
        else
            cmd=(qemu-img create -f qcow2 "$disk_path" "${size}G")
        fi
        "${cmd[@]}" &>/dev/null || return 1
    fi
    chmod 644 "$disk_path"
    echo "$disk_path"
}

remove_existing_vm() {
    local vm_name="$1"
    if virsh dominfo "$vm_name" &>/dev/null; then
        warn "VM '$vm_name' already exists. Removing..."
        virsh destroy "$vm_name" &>/dev/null || true
        virsh undefine "$vm_name" &>/dev/null || true
        log "Removed existing VM '$vm_name'."
    fi
}

wait_for_guest_agent() {
    local vm_name="$1" timeout="${2:-300}" elapsed=0
    log "Waiting for guest agent on '$vm_name' (timeout ${timeout}s)..."
    while (( elapsed < timeout )); do
        if virsh qemu-agent-command "$vm_name" '{"execute":"guest-ping"}' &>/dev/null; then
            log "Guest agent ready."
            return 0
        fi
        sleep 5
        (( elapsed += 5 ))
    done
    error "Guest agent not ready after ${timeout}s."
    return 1
}

get_libvirt_xml() {
    local vm_name="$1" ram="$2" cpu="$3" disk_path="$4"
    local iso_path="${5:-}" cloud_init="${6:-}" virtio_win="${7:-}" windows_auto="${8:-}"

    local devices_xml=""
    devices_xml+="
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='$disk_path'/>
              <target dev='vda' bus='virtio'/>
            </disk>"

    local cdroms=()
    [[ -n "$iso_path" ]] && cdroms+=("$iso_path")
    [[ -n "$cloud_init" ]] && cdroms+=("$cloud_init")
    [[ -n "$virtio_win" ]] && cdroms+=("$virtio_win")
    [[ -n "$windows_auto" ]] && cdroms+=("$windows_auto")

    local idx=0
    for cd in "${cdroms[@]}"; do
        local dev
        dev=$(printf "sd\\x$(printf '%x' $((97 + idx)))")
        devices_xml+="
            <disk type='file' device='cdrom'>
              <driver name='qemu' type='raw'/>
              <source file='$cd'/>
              <target dev='$dev' bus='sata'/>
              <readonly/>
            </disk>"
        (( idx++ ))
    done

    cat << XMLEOF
<domain type='kvm'>
  <name>$vm_name</name>
  <memory unit='MiB'>$ram</memory>
  <vcpu placement='static'>$cpu</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
    <boot dev='cdrom'/>
  </os>
  <features>
    <acpi/><apic/><pae/>
  </features>
  <cpu mode='host-passthrough'/>
  <devices>
    $devices_xml
    <interface type='network'>
      <source network='$NETWORK_NAME'/>
      <model type='virtio'/>
    </interface>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <input type='tablet' bus='usb'/>
    <graphics type='spice' autoport='yes'/>
    <video>
      <model type='qxl'/>
    </video>
  </devices>
</domain>
XMLEOF
}

main() {
    echo -e "${GREEN}=== VM Preparation Tool ===${NC}"

    check_deps || exit 1
    check_libvirt || exit 1
    get_input_zenity || { error "Cancelled."; exit 1; }

    mkdir -p "$DATA_DIR"
    chmod 755 "$DATA_DIR"

    echo -e "\n${GREEN}Configuration:${NC}"
    echo "  VM Name:      $VM_NAME"
    echo "  Distro:       $DISTRO"
    echo "  RAM:          ${RAM} MiB"
    echo "  CPU:          ${CPU} cores"
    echo "  Disk:         ${DISK_SIZE} GiB"
    echo ""

    # Phase 1: Network
    {
        echo "10"
        echo "# Ensuring network..."
        ensure_network || { error "Network setup failed."; exit 1; }
        echo "15"

        # Phase 2: Download images
        echo "# Downloading images..."
        mkdir -p "$DOWNLOAD_DIR"

        IMAGE_PATH=""
        CLOUD_INIT_PATH=""
        VIRTIO_WIN_PATH=""
        WINDOWS_AUTO_PATH=""
        PROCMON_PATH=""

        if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
            local url
            if [[ "$DISTRO" == "ubuntu" ]]; then
                url="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
            else
                url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
            fi
            IMAGE_PATH="$DOWNLOAD_DIR/$(basename "$url")"
            download_file "$url" "$IMAGE_PATH" || { error "Download failed."; exit 1; }
            echo "20"

            echo "# Creating Cloud-Init ISO..."
            local tmpdir
            tmpdir=$(mktemp -d)
            CLOUD_INIT_PATH="$DATA_DIR/$VM_NAME-cloud-init.iso"
            mkdir -p "$DATA_DIR"
            create_cloud_init_iso "$VM_NAME" "$tmpdir" "$CLOUD_INIT_PATH" || {
                error "Failed to create Cloud-Init ISO."
                rm -rf "$tmpdir"
                exit 1
            }
            rm -rf "$tmpdir"
        elif [[ "$DISTRO" == "windows" ]]; then
            url="https://software-static.download.prss.microsoft.com/db_releases/Windows_11_Enterprise_Evaluation_Multi.iso"
            IMAGE_PATH="$DOWNLOAD_DIR/windows11.iso"
            download_file "$url" "$IMAGE_PATH" || { error "Download failed."; exit 1; }
            echo "20"

            echo "# Downloading VirtIO drivers..."
            VIRTIO_WIN_PATH="$DOWNLOAD_DIR/virtio-win.iso"
            download_file "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso" "$VIRTIO_WIN_PATH"
            echo "25"

            echo "# Downloading Procmon..."
            PROCMON_PATH="$DOWNLOAD_DIR/ProcessMonitor.zip"
            download_file "https://download.sysinternals.com/files/ProcessMonitor.zip" "$PROCMON_PATH"
            echo "30"
        fi
        echo "40"

        # Phase 3: Create disk
        echo "# Creating disk image..."
        local actual_disk
        actual_disk=$(create_disk "$DISK_DIR/$VM_NAME.qcow2" "$DISK_SIZE" "$IMAGE_PATH") || {
            error "Failed to create disk."
            exit 1
        }
        echo "50"

        # Phase 4: Define VM
        echo "# Defining VM in libvirt..."
        remove_existing_vm "$VM_NAME"

        local xml
        xml=$(get_libvirt_xml "$VM_NAME" "$RAM" "$CPU" "$actual_disk" \
            "$([[ $DISTRO == windows ]] && echo "$IMAGE_PATH")" \
            "$CLOUD_INIT_PATH" \
            "$VIRTIO_WIN_PATH" \
            "$WINDOWS_AUTO_PATH")

        virsh define /dev/stdin <<<"$xml" || { error "Failed to define VM."; exit 1; }
        echo "60"

        # Phase 5: Start VM
        echo "# Starting VM..."
        virsh start "$VM_NAME" || { error "Failed to start VM."; exit 1; }
        echo "70"

        # Phase 6: Wait for guest agent
        echo "# Waiting for guest agent (this may take 2-5 minutes)..."
        wait_for_guest_agent "$VM_NAME" 300 || { error "Guest agent timeout."; exit 1; }
        echo "80"

        # Phase 7: Install tools
        if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
            echo "# Installing strace, tcpdump..."
            virsh qemu-agent-command "$VM_NAME" \
                '{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c","apt-get update && apt-get install -y strace tcpdump"],"capture-output":true}}' \
                &>/dev/null || true
        fi
        echo "90"

        # Phase 8: Snapshot
        echo "# Taking 'clean-baseline' snapshot..."
        virsh snapshot-create-as "$VM_NAME" "clean-baseline" "Automated baseline" || {
            error "Failed to create snapshot."
            exit 1
        }
        echo "100"

    } | zenity --progress \
        --title="VM Preparation" \
        --text="Starting..." \
        --percentage=0 \
        --auto-close \
        --width=500 2>/dev/null

    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log "VM Preparation COMPLETED SUCCESSFULLY!"
        zenity --info --title="VM Preparation" \
            --text="VM '$VM_NAME' is ready.\n\nBaseline snapshot 'clean-baseline' created." \
            2>/dev/null || true
    else
        error "Preparation failed."
        zenity --error --title="VM Preparation" \
            --text="VM preparation failed. Check terminal for details." \
            2>/dev/null || true
    fi
}

main "$@"
