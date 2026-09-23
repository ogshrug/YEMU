# YEMU

YEMU is a local malware analysis sandbox with a GTK4 / libadwaita desktop UI. It runs a sample inside a disposable QEMU/KVM virtual machine, watches what it does, scans it with YARA, and gives it a 0–100 threat score and a verdict.

> [!WARNING]
> This tool executes real malware. Only run samples on a host you are willing to lose, and check the VM network before every run (see [Safety](#safety)). The project is under active development and is not yet hardened for production use.

## How it works

```
 sample ──► static YARA scan (host)
        │
        ├─► revert VM to "clean-baseline" snapshot ─► start VM ─► wait for qemu-guest-agent
        │
        ├─► inject sample into the guest ─► run under strace (+ optional tcpdump)
        │
        ├─► in-guest YARA scan of /proc memory
        │
        ├─► collect strace logs / PCAP ─► parse behaviour & network IOCs
        │
        └─► threat score + verdict ─► SQLite + JSON/PDF report ─► stop VM
```

| Stage | Module |
|---|---|
| Pipeline orchestration | `core/orchestrator.py` |
| VM control (libvirt, `virsh qemu-agent-command`, `virt-copy-in/out`) | `core/vm_manager.py` |
| YARA scanning and rule compilation | `core/yara_engine.py` |
| Rule sync from GitHub (default: [Yara-Rules/rules](https://github.com/Yara-Rules/rules)) | `core/yara_sync.py` |
| strace / Procmon parsing | `core/behaviour_monitor.py` |
| PCAP → IP and domain IOCs (scapy) | `core/network_capture.py` |
| Scoring and verdict | `core/threat_scorer.py` |
| SQLite storage (`samples`, `analyses`, `events`, `iocs`) | `storage/db.py` |
| JSON and PDF reports | `storage/report_store.py`, `core/report_generator.py` |

### Scoring

| Finding | Points |
|---|---|
| Any YARA match | +40 (+10 more if there are over 3 matches) |
| Network C2 alert | +30 |
| Suspicious syscalls | +5 each, max +20 |
| Persistence | +10 |

The score is capped at 100. Under 30 is **clean**, 30–69 is **suspicious**, and 70 or more is **malicious**.

## Platform support

| Host | Status |
|---|---|
| Linux (Ubuntu 22.04+ / Debian 12+) with KVM | Supported |
| Windows 11 through WSL2 (WSLg + nested virtualization) | Untested. Planned. |
| Native Windows | Not supported. Needs a non-libvirt VM backend. |

Guest VMs are Linux (Ubuntu or Debian cloud images) for automated analysis. A Windows 11 guest can be provisioned, but the automated pipeline (strace, `/proc` scanning) only works on Linux guests today.

If KVM or libvirt isn't available, or your user isn't in the `libvirt`/`kvm` groups, the app starts in **Mock Mode**. Mock Mode uses canned data so you can explore the UI.

## Installation (Linux)

Requirements: a CPU with VT-x or AMD-V, virtualization enabled in firmware, and Python 3.10+.

```bash
# System packages
sudo apt update
sudo apt install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
  virt-manager virt-viewer libguestfs-tools genisoimage zenity \
  python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
  libgtksourceview-5-dev python3-libvirt strace tcpdump yara

# Let your user talk to libvirt/KVM (then log out and back in)
sudo usermod -aG libvirt,kvm "$USER"

# Python packages
python3 -m venv .venv --system-site-packages   # system site-packages exposes PyGObject/libvirt
source .venv/bin/activate
pip install -r requirements.txt
```

You can also run `make install`, which installs the system and Python packages in one step.

## Preparing an analysis VM

The pipeline needs a libvirt domain that has **qemu-guest-agent** running and a snapshot named **`clean-baseline`**.

### Automated

Click **Prepare New VM** in the app, or run `bash ui/prepare_vm.sh`. The script:

1. Creates the `malware-analysis` libvirt network (`192.168.100.0/24`).
2. Downloads an Ubuntu 24.04 or Debian 12 cloud image, or a Windows 11 evaluation ISO plus VirtIO drivers.
3. Builds a cloud-init seed that installs `qemu-guest-agent`, `strace` and `tcpdump`.
4. Defines and boots the VM, waits for the guest agent, then takes the `clean-baseline` snapshot.

Images and disks are stored in `/tmp/gpcssi-$USER/`.

### Manual

1. Create a VM in `virt-manager`, for example `ubuntu-clean`.
2. Inside the guest, install and enable the agent and the monitoring tools:
   ```bash
   sudo apt install -y qemu-guest-agent strace tcpdump yara
   sudo systemctl enable --now qemu-guest-agent
   ```
3. Make sure the domain XML has the agent channel:
   ```xml
   <channel type='unix'>
     <target type='virtio' name='org.qemu.guest_agent.0'/>
   </channel>
   ```
4. Attach the VM to the `malware-analysis` network, then take the snapshot:
   ```bash
   virsh snapshot-create-as ubuntu-clean clean-baseline "Clean state for analysis"
   ```

## Usage

```bash
python main.py        # or: make run
```

1. Pick a **VM** and **snapshot** in the sidebar.
2. Optionally enable **GUI**, which opens `virt-viewer` for manual analysis and skips automated monitoring. You can also enable **PCAP** to capture guest traffic.
3. Click **Submit File for Analysis** and choose a sample.
4. Watch progress in the log stream at the bottom. When the run finishes, the **Dashboard** shows the score, YARA hits and behaviour events.
5. Open earlier runs from **Recent Analyses**. Use the **Reports** tab to read the full report or **Export to PDF**.
6. Use the **YARA Rules** tab to browse, edit and create rules, or to **Sync Rules** from any GitHub repo and branch. You can also sync from the command line with `make sync-rules`.

### Where data goes

| What | Where |
|---|---|
| Database | `malware_sandbox.db` (working directory) |
| Reports | `assets/reports/report_<id>.{json,pdf}` |
| PCAPs | `storage/captures/<id>.pcap` |
| Built-in rules | `rules/default.yar` |
| Synced rules | `rules/yara-rules/` |

## Safety

- **Check the network isolation.** `ui/prepare_vm.sh` defines `malware-analysis` with `<forward mode='nat'/>`, which gives the guest **internet access**. For truly offline analysis, remove the `<forward>` element, or redefine the network without it:
  ```bash
  virsh net-dumpxml malware-analysis   # confirm there is no <forward> element
  ```
- The cloud-init seed sets a fixed guest password (`analysis-password`) and enables SSH password login. Treat the guest as untrusted and never bridge it to your LAN.
- Always analyse from a reverted snapshot. The pipeline reverts automatically, but manual (GUI) sessions leave the VM running.

## Testing

```bash
pip install pytest pytest-asyncio
pytest -q
```

`test_core.py` covers the scorer, the YARA engine and pipeline resilience with a failing VM backend. `test_fix.py` covers the libvirt fallback and Mock Mode. `test_yara_sync.py` covers rule sync. None of the tests need a real VM.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied` | Add yourself to the `libvirt` and `kvm` groups and log in again. The app falls back to `qemu:///session` automatically. |
| `virt-copy-in` / libguestfs: `cannot access /boot/vmlinuz` | `sudo chmod +r /boot/vmlinuz-*`. The app already sets `LIBGUESTFS_BACKEND=direct`. |
| "VM not found" | Check `virsh list --all`. The name must match exactly. |
| Guest agent timeout | Check that the agent channel exists in the domain XML and that `systemctl status qemu-guest-agent` shows it running in the guest. |
| `malware-analysis` network missing | The app tries to create it. To create it manually, use `virsh net-define <xml>`, then `virsh net-start malware-analysis` and `virsh net-autostart malware-analysis`. |
| App shows "Mock Mode" | libvirt/KVM isn't reachable. See the first row. |

## Project layout

```
main.py              Entry point (Adw.Application, CSS)
core/                Pipeline, VM control, YARA, parsing, scoring, provisioning
storage/             SQLite access layer and report writer
ui/                  GTK4 widgets and the VM-preparation script
rules/               Built-in YARA rules and the synced-rules directory
assets/reports/      Generated reports
test_*.py            pytest suites
```
