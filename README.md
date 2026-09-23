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
| Pipeline orchestration | `yemu/core/orchestrator.py` |
| VM backend interface and factory | `yemu/core/vm_backend.py` |
| libvirt backend and mock backend | `yemu/core/vm_manager.py` |
| YARA scanning and rule compilation | `yemu/core/yara_engine.py` |
| Rule sync from GitHub (default: [Yara-Rules/rules](https://github.com/Yara-Rules/rules)) | `yemu/core/yara_sync.py` |
| strace / Procmon parsing | `yemu/core/behaviour_monitor.py` |
| PCAP → IP and domain IOCs (scapy) | `yemu/core/network_capture.py` |
| Scoring and verdict (weights set in config) | `yemu/core/threat_scorer.py` |
| SQLite storage (`samples`, `analyses`, `events`, `iocs`) | `yemu/storage/db.py` |
| JSON and PDF reports | `yemu/storage/report_store.py`, `yemu/core/report_generator.py` |
| Per-user paths and settings | `yemu/paths.py`, `yemu/config.py` |
| CLI and GUI entry points | `yemu/cli.py`, `yemu/app.py` |

### Scoring

| Finding | Points |
|---|---|
| Any YARA match | +40 (+10 more if there are over 3 matches) |
| Network C2 alert | +30 |
| Suspicious syscalls | +5 each, max +20 |
| Persistence | +10 |

The score is capped at 100. Under 30 is **clean**, 30–69 is **suspicious**, and 70 or more is **malicious**. You can change every weight and threshold in the `[scoring]` section of the config file.

## Platform support

| Host | CLI (`yemu`) + mock backend | Real VM analysis | Desktop app |
|---|---|---|---|
| Linux (Ubuntu 22.04+ / Debian 12+) with KVM | Yes | Yes (libvirt) | Yes |
| Windows 11 | Yes | Not yet. Use WSL2 (planned) | Not yet. Use WSL2 + WSLg (planned) |
| Windows 11 through WSL2 | Yes | Untested | Untested |

On every host, YEMU can run static YARA analysis, keep past analyses and reports, sync rules, and run the whole pipeline against the **mock backend**. Actually detonating samples needs a VM backend. Today that means libvirt/KVM on Linux. A Windows backend is planned.

Guest VMs are Linux (Ubuntu or Debian cloud images) for automated analysis. A Windows 11 guest can be provisioned, but the automated pipeline (strace, `/proc` scanning) only works on Linux guests today.

With the default `backend = "auto"`, YEMU falls back to **Mock Mode** when libvirt isn't reachable. Mock Mode uses canned VM responses, so you can explore the UI and CLI.

## Installation

Requires Python 3.10+.

### Linux (full install)

Requirements: a CPU with VT-x or AMD-V, and virtualization enabled in firmware.

```bash
make install-system                       # apt: qemu/kvm, libvirt, libguestfs, GTK4, libadwaita, yara...
sudo usermod -aG libvirt,kvm "$USER"      # then log out and back in

python3 -m venv .venv --system-site-packages   # exposes the distro's PyGObject/libvirt
source .venv/bin/activate
pip install -e ".[linux,dev]"
yemu doctor                               # checks everything is in place
```

### Windows (CLI, mock backend)

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
yemu doctor
```

## Where data goes

| What | Linux | Windows |
|---|---|---|
| Database, reports, captures, synced rules | `~/.local/share/yemu/` | `%LOCALAPPDATA%\YEMU\` |
| Config file | `~/.config/yemu/config.toml` | `%LOCALAPPDATA%\YEMU\config.toml` |
| VM disks and base images | `/var/tmp/yemu-$USER/` (must be readable by QEMU) | `%LOCALAPPDATA%\YEMU\vms\` |
| Built-in rules (always loaded) | `yemu/rules/default.yar` | same |

`yemu paths` prints the real locations on your machine. Set `YEMU_HOME=<dir>` to keep everything in one folder (portable installs, tests). Set `YEMU_VM_DIR` to move VM storage.

## Configuration

```bash
yemu config --init    # writes a commented config.toml with the defaults
yemu config           # shows the effective settings
```

| Section | Keys |
|---|---|
| `[vm]` | `backend` (`auto`/`libvirt`/`mock`), `default_vm`, `default_snapshot`, `agent_timeout` |
| `[network]` | `name`, `allow_internet` (turns off the isolation warning) |
| `[analysis]` | `execution_wait` (seconds before logs are collected) |
| `[scoring]` | score weights and verdict thresholds |
| `[rules]` | `repo_url`, `branch` for rule sync |

## Preparing an analysis VM

The pipeline needs a libvirt domain that has **qemu-guest-agent** running and a snapshot named **`clean-baseline`**.

### Automated

Click **Prepare New VM** in the app (Linux only). For scripted setups, run the equivalent shell version: `bash scripts/prepare_vm.sh`. Both of them:

1. Creates two libvirt networks:
   - `malware-analysis` (`192.168.100.0/24`) is **isolated**, with no internet access. Analysis runs here.
   - `yemu-provision` (`192.168.101.0/24`) uses NAT and is only used while the guest installs its tools.
2. Downloads an Ubuntu 24.04 or Debian 12 cloud image, or a Windows 11 evaluation ISO plus VirtIO drivers.
3. Builds a cloud-init seed that installs `qemu-guest-agent`, `strace` and `tcpdump`.
4. Defines and boots the VM on `yemu-provision`, then waits for the guest agent.
5. Moves the VM onto `malware-analysis`, reboots it, then takes the `clean-baseline` snapshot.

Images and disks are stored in `/var/tmp/yemu-$USER/`. A random guest console password is generated for each VM. The app shows it in the preparation log. The script saves it to `/var/tmp/yemu-$USER/<vm>.credentials` (mode 600), and you can move the script's storage with `YEMU_DATA_DIR`.

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

### Desktop app (Linux)

```bash
yemu gui              # or: python main.py
```

1. Pick a **VM** and **snapshot** in the sidebar.
2. Optionally enable **GUI**, which opens `virt-viewer` for manual analysis and skips automated monitoring. You can also enable **PCAP** to capture guest traffic.
3. Click **Submit File for Analysis** and choose a sample.
4. Watch progress in the log stream at the bottom. When the run finishes, the **Dashboard** shows the score, YARA hits and behaviour events.
5. Open earlier runs from **Recent Analyses**. Use the **Reports** tab to read the full report or **Export to PDF**.
6. Use the **YARA Rules** tab to browse, edit and create rules, or to **Sync Rules** from any GitHub repo and branch.

### Command line (Linux and Windows)

```bash
yemu analyze sample.bin                      # uses [vm] defaults from config
yemu analyze sample.bin --vm ubuntu-clean --snapshot clean-baseline --pcap
yemu analyze sample.bin --backend mock --json
yemu reports                                  # recent analyses
yemu report 12                                # one analysis + events, as JSON
yemu list-vms
yemu sync-rules [--repo URL --branch BRANCH]
yemu paths | yemu config [--init] | yemu doctor
```

`yemu analyze` exits with **3** when the verdict is `malicious`, so you can use it in scripts and pipelines.

## Safety

- **The analysis network is offline by default.** Before every run, YEMU checks the VM's interfaces. If any interface can reach the host LAN or the internet (a NAT or routed libvirt network, or a bridge/direct interface), it logs a `CRITICAL` warning. To deliberately give samples internet access, provision with `YEMU_ALLOW_INTERNET=1 bash scripts/prepare_vm.sh`, and set `allow_internet = true` under `[network]` in the config.
  ```bash
  virsh net-dumpxml malware-analysis   # an isolated network has no <forward> element
  ```
- VMs created by older versions of the script used a NAT network and the fixed password `analysis-password`. Re-run **Prepare New VM** to rebuild them.
- Guest SSH password login is disabled. YEMU talks to the guest only through qemu-guest-agent. Treat the guest as untrusted and never bridge it to your LAN.
- Always analyse from a reverted snapshot. The pipeline reverts automatically, but manual (GUI) sessions leave the VM running.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

Tests live in `tests/` and run on Linux and Windows. None of them need a real VM, and they never write to your real data folders, because each test gets its own `YEMU_HOME`.

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
yemu/
  app.py             GTK4 / libadwaita application
  cli.py             `yemu` command-line interface
  paths.py           per-user data/config/cache locations
  config.py          config.toml loading and defaults
  core/              pipeline, VM backends, YARA, parsing, scoring, provisioning
  storage/           SQLite access layer and report writer
  ui/                GTK widgets and the VM-preparation window
  rules/default.yar  built-in YARA rules
scripts/prepare_vm.sh  shell version of VM preparation (Linux)
tests/               pytest suites
main.py              compatibility launcher for the GUI
```
