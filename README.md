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

## Setup & Usage

1. **Initialize Libvirt Network**:
   Ensure the `malware-analysis` network is defined in libvirt with no internet access.

2. **Prepare Guest VMs**:
   Create a VM named `ubuntu-clean` (or `mint`, `alpine`, `windows`) and take a snapshot named `clean-baseline`.

3. **Run the App**:
   ```bash
   python main.py
   ```

## Development & Mock Mode
If you don't have KVM available, the application supports a Mock Mode for UI demonstration.

## Project Structure
- `ui/`: GTK4 Interface components
- `core/`: Analysis engines and VM management
- `storage/`: Database and report persistence
- `rules/`: YARA rulesets
- `assets/`: Styling and ISO templates
