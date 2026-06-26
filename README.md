# Local Malware Analysis Sandbox

A local, offline malware analysis sandbox with a GTK4 GUI. Isolated VM execution via QEMU/KVM and behavioral monitoring.

## Features
- Isolated VM Execution (QEMU/KVM)
- Behavioral Monitoring (strace, network capture)
- YARA Static & Memory Analysis
- Threat Scoring & Verdict Generation
- Real-time Log Streaming
- PDF & JSON Reporting

## Prerequisites

### System Dependencies (Ubuntu/Debian)
```bash
sudo apt install qemu-kvm libvirt-daemon-system virt-manager \
  python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
  libgtksourceview-5-dev strace tcpdump yara
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

# Usage

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

The sandbox requires a pre-configured Virtual Machine in libvirt. You can either prepare it manually or use the built-in automated tool.

### Automated VM Preparation (Recommended)
1. Launch MalSandbox: `python main.py`.
2. Click **Prepare New VM**.
3. Fill in the VM Name, Distro (Ubuntu, Debian, or Windows), RAM, CPU, and Disk size.
4. Click **Prepare VM** and wait for the process to complete (this includes downloading images, automated installation, and snapshotting).

### Manual VM Preparation
1. **Create a VM**: Use `virt-manager` to create a VM (e.g., named `ubuntu-clean`).
2. **Install Guest Agent**: Ensure `qemu-guest-agent` is installed and running inside the guest OS.
3. **Configure Network**: The VM should be on an isolated network named `malware-analysis`.
4. **Take a Snapshot**: Once configured, take a snapshot named `clean-baseline`.
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

- **Libvirt Connection / Permission Errors**
  If you see "Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied", it's likely a group membership issue.
  Ensure your user is in the `libvirt` and `kvm` groups:
  ```bash
  sudo usermod -aG libvirt,kvm $USER
  # You must log out and log back in for this to take effect.
  ```
  The application will automatically attempt to use `qemu:///session` if `qemu:///system` is inaccessible.

- **Libguestfs Kernel Access Errors**
  If automated VM preparation or `virt-copy-in` fails with "cannot access /boot/vmlinuz", fix it by granting read permissions to the kernel images:
  ```bash
  sudo chmod +r /boot/vmlinuz-*
  ```
  The app also sets `LIBGUESTFS_BACKEND=direct` internally to bypass some common permission issues.

- **VM Domain Not Found**
  If you get an error stating a VM was not found, verify that it appears in `virsh list --all`.
  ```bash
  virsh list --all
  ```
  If it's missing, use the **Prepare New VM** button to create it or create it manually via `virt-manager` ensuring the name matches.

- **QEMU Guest Agent Not Responding**
  If the guest agent times out, ensure:
  1. The VM has the guest agent channel configured:
     ```xml
     <channel type='unix'>
       <target type='virtio' name='org.qemu.guest_agent.0'/>
     </channel>
     ```
  2. The `qemu-guest-agent` service is installed and running inside the guest OS:
     ```bash
     # Inside Ubuntu/Debian guest
     sudo apt install qemu-guest-agent
     sudo systemctl enable --now qemu-guest-agent
     ```

- **Isolated Network Issues**
  If the `malware-analysis` network is missing, the app will try to auto-define it. You can also do it manually:
  ```bash
  virsh net-define assets/network.xml
  virsh net-start malware-analysis
  virsh net-autostart malware-analysis
  ```

- **Mock Mode Fallback**
  If the app cannot find KVM or libvirt resources, it will automatically degrade to **Mock Mode**. A warning will be displayed in the Log Stream. This allows you to explore the UI even without a local virtualization setup.
## Project Structure
- `ui/`: GTK4 Interface components
- `core/`: Analysis engines and VM management
- `storage/`: Database and report persistence
- `rules/`: YARA rulesets
- `assets/`: Styling and ISO templates
