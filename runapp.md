# Running MalSandbox

This guide explains how to set up and run the Malware Analysis Sandbox.

## Prerequisites

### System Requirements
- Ubuntu 22.04+ (or equivalent Linux distribution)
- CPU with VT-x/AMD-V support (for KVM)
- Libvirt and QEMU installed

### Dependencies
Install the required system packages:
```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients virt-manager \
  libguestfs-tools gir1.2-gtk-4.0 gir1.2-adw-1 python3-gi python3-libvirt
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

## VM Preparation

The sandbox requires a pre-configured Virtual Machine in libvirt.

1. **Create a VM**: Use `virt-manager` to create a VM (e.g., named `ubuntu-clean`).
2. **Install Guest Agent**: Ensure `qemu-guest-agent` is installed and running inside the guest OS.
3. **Configure Network**: The VM should ideally be on an isolated network.
4. **Take a Snapshot**: Once the VM is configured, take a snapshot named `clean-baseline`.
   ```bash
   virsh snapshot-create-as ubuntu-clean clean-baseline "Clean state for analysis"
   ```

## Running the Application

Start the application by running:
```bash
python main.py
```

## User Interface Guide

### 1. Header Bar
- **Stack Switcher**: Located in the center of the header. Use it to navigate between the **Dashboard**, **YARA Rules**, and **Reports** tabs.
- **Submit File for Analysis**: Clicking this button will submit the `malicious_sample.elf` for analysis.

### 2. Dashboard
- Displays high-level metrics of the last analysis:
  - **Threat Score**: A value from 0-100 indicating the severity.
  - **YARA Matches**: Number of static signatures triggered.
  - **Behavioral Alerts**: Number of suspicious syscalls detected.

### 3. YARA Rules
- View and edit the YARA rules used for static analysis.
- The app automatically loads rules from `rules/yara-rules`.

### 4. Reports
- Detailed view of past analyses, including metadata, logs, and findings.

### 5. Sidebar
- **Recent Analyses**: A list of recently completed analysis tasks. Click one to view its report.

### 6. Log Viewer
- Located at the bottom. Shows real-time progress of the analysis, including VM lifecycle events and YARA matches.

## Troubleshooting

- **Libvirt Connection Error**: Ensure your user is in the `libvirt` and `kvm` groups.
  ```bash
  sudo usermod -aG libvirt,kvm $USER
  ```
- **Libguestfs Permissions**: On some systems (like Ubuntu), libguestfs might fail to access the kernel. Fix this by running:
  ```bash
  sudo chmod +r /boot/vmlinuz-*
  # OR set LIBGUESTFS_BACKEND
  export LIBGUESTFS_BACKEND=direct
  ```
- **VM Not Found**: Check that the VM name in `core/orchestrator.py` (default: `ubuntu-clean`) matches your libvirt domain name.
- **Guest Agent Not Responding**: Ensure the VM has a `virtio-serial` channel named `org.qemu.guest_agent.0` and `qemu-guest-agent` is running inside.
