# YEMU

YEMU is a local malware analysis sandbox for Linux and Windows. It runs a sample inside a disposable QEMU virtual machine (KVM on Linux, Windows Hypervisor Platform on Windows), watches what it does, scans it with YARA, and gives it a 0–100 threat score and a verdict. It has a command-line tool (`yemu`) and a GTK4 / libadwaita desktop app.

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
| Standalone QEMU backend (Windows + Linux) and guest-agent client | `yemu/core/qemu_backend.py`, `yemu/core/qga.py` |
| Shared VM preparation flow | `yemu/core/provisioning.py`, `yemu/core/vm_provisioner.py` |
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

| Host | CLI (`yemu`) | Real VM analysis | Desktop app |
|---|---|---|---|
| Linux (Ubuntu 22.04+ / Debian 12+) | Yes | Yes: `libvirt` backend (KVM) or `qemu` backend | Yes |
| Windows 10/11 | Yes | Yes: `qemu` backend with WHPX acceleration | Not yet. Use WSL2 + WSLg |
| Windows through WSL2 | Yes | Yes (needs nested virtualization for KVM speed) | Yes, through WSLg |

YEMU has three VM backends. `[vm].backend = "auto"` (the default) picks the first one that works:

| Backend | Hosts | How it works |
|---|---|---|
| `libvirt` | Linux | libvirt/QEMU-KVM domains, `virsh`, libguestfs, isolated libvirt networks, and live memory snapshots |
| `qemu` | Windows, Linux | Runs `qemu-system-x86_64` directly and talks to the guest agent over a local socket. Uses WHPX, KVM or TCG acceleration. Uses QEMU user-mode networking (`restrict=on` for analysis). Snapshots are qcow2 disk snapshots |
| `mock` | any | Canned responses, so you can explore the UI and CLI without a hypervisor |

Automated analysis needs Linux guests (Ubuntu or Debian cloud images). A Windows 11 guest can be provisioned on the `libvirt` backend, but the automated pipeline (strace, `/proc` scanning) only works on Linux guests today.

## Installation

Requires Python 3.10+ and a CPU with VT-x or AMD-V enabled in firmware.

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 -CreateVM ubuntu-clean
```

The script:

1. Installs QEMU with winget if it's missing.
2. Checks **Windows Hypervisor Platform** (run it as admin to have the feature enabled for you).
3. Creates `.venv`, installs YEMU into it and runs `yemu doctor`.
4. With `-CreateVM`, it also builds the analysis VM.

To do the same by hand:

```powershell
winget install SoftwareFreedomConservancy.QEMU
# Admin PowerShell, then reboot:
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
py -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
yemu doctor
yemu vm create ubuntu-clean
```

### Linux (including WSL2)

```bash
bash scripts/setup_linux.sh               # libvirt + GTK app + CLI
bash scripts/setup_linux.sh --qemu-only   # lighter: standalone QEMU backend + CLI
```

The script installs the apt packages and adds you to the `libvirt` and `kvm` groups (log out and back in afterwards). It then creates `.venv` with system site-packages, which gives it the distro's PyGObject and libvirt, and runs `pip install -e ".[linux,dev]"`.

Inside **WSL2**, the script also:

- Turns on systemd in `/etc/wsl.conf`, because libvirtd needs it.
- Tells you if `/dev/kvm` is missing. To fix that, add the following to `%UserProfile%\.wslconfig` and run `wsl --shutdown`:
  ```ini
  [wsl2]
  nestedVirtualization=true
  ```
- WSLg displays the desktop app on Windows 11.

## Where data goes

| What | Linux | Windows |
|---|---|---|
| Database, reports, captures, synced rules | `~/.local/share/yemu/` | `%LOCALAPPDATA%\YEMU\` |
| Config file | `~/.config/yemu/config.toml` | `%LOCALAPPDATA%\YEMU\config.toml` |
| VM disks and base images | `/var/tmp/yemu-$USER/` (must be readable by QEMU) | `%LOCALAPPDATA%\YEMU\vms\` |
| `qemu` backend VMs (config, disk, console log) | `<VM storage>/qemu/<name>/` | same |
| Built-in rules (always loaded) | `yemu/rules/default.yar` | same |

`yemu paths` prints the real locations on your machine. Set `YEMU_HOME=<dir>` to keep everything in one folder (portable installs, tests). Set `YEMU_VM_DIR` to move VM storage.

## Configuration

```bash
yemu config --init    # writes a commented config.toml with the defaults
yemu config           # shows the effective settings
```

| Section | Keys |
|---|---|
| `[vm]` | `backend` (`auto`/`libvirt`/`qemu`/`mock`), `default_vm`, `default_snapshot`, `agent_timeout` |
| `[qemu]` | `bin_dir` (where QEMU is installed, if not on PATH), `accel` (`auto`/`whpx`/`kvm`/`hvf`/`tcg`), `extra_args` |
| `[network]` | `name`, `allow_internet` (turns off the isolation warning) |
| `[analysis]` | `execution_wait` (seconds before logs are collected) |
| `[scoring]` | score weights and verdict thresholds |
| `[rules]` | `repo_url`, `branch` for rule sync |

## Preparing an analysis VM

The pipeline needs a VM that has **qemu-guest-agent** running and a snapshot named **`clean-baseline`**.

### Automated (recommended, on any host)

```bash
yemu vm create ubuntu-clean               # --distro debian, --ram 4096, --cpus 4, --disk 40, --backend qemu
```

The desktop app's **Prepare New VM** button runs the same flow:

1. Downloads an Ubuntu 24.04 or Debian 12 cloud image. It's cached, so the next VM reuses it.
2. Builds a cloud-init seed. The seed installs `qemu-guest-agent`, `strace`, `tcpdump` and `yara`, sets a random console password and turns off SSH password login.
3. Boots the VM on a **NAT** network so the guest can install its tools (`yemu-provision` on libvirt, user-mode NAT on qemu).
4. Moves the VM onto the **isolated** analysis network: `malware-analysis` with no `<forward>` on libvirt, or `restrict=on` on qemu. Then it checks that the VM can no longer reach the internet.
5. Takes the `clean-baseline` snapshot and prints the console password.

Other VM commands: `yemu vm list`, `yemu vm start <name> [--console]`, `yemu vm stop <name>` and `yemu vm delete <name> --yes` (qemu backend).

`scripts/prepare_vm.sh` is the older zenity-based shell version for libvirt. It follows the same network model and saves the password to `/var/tmp/yemu-$USER/<vm>.credentials`.

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

### Desktop app (Linux, or Windows through WSLg)

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
yemu vm create ubuntu-clean                  # once
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

- **The analysis network is offline by default.** Before every run, YEMU checks the VM's interfaces. If any interface can reach the host LAN or the internet, it logs a `CRITICAL` warning. On libvirt that means a NAT or routed network, or a bridge/direct interface. On qemu it means user-mode networking without `restrict=on`. To deliberately give samples internet access, provision with `YEMU_ALLOW_INTERNET=1 bash scripts/prepare_vm.sh`, and set `allow_internet = true` under `[network]` in the config.
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

Tests live in `tests/`. CI (`.github/workflows/tests.yml`) runs them on Ubuntu and Windows with Python 3.10 and 3.12. None of them need a real VM, and they never write to your real data folders, because each test gets its own `YEMU_HOME`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied` | Add yourself to the `libvirt` and `kvm` groups and log in again. The app falls back to `qemu:///session` automatically. |
| `virt-copy-in` / libguestfs: `cannot access /boot/vmlinuz` | `sudo chmod +r /boot/vmlinuz-*`. The app already sets `LIBGUESTFS_BACKEND=direct`. |
| "VM not found" | Check `virsh list --all`. The name must match exactly. |
| Guest agent timeout | Check that the agent channel exists in the domain XML and that `systemctl status qemu-guest-agent` shows it running in the guest. |
| `malware-analysis` network missing | The app tries to create it. To create it manually, use `virsh net-define <xml>`, then `virsh net-start malware-analysis` and `virsh net-autostart malware-analysis`. |
| App shows "Mock Mode" | No backend is available. Run `yemu doctor`: it checks QEMU, acceleration, libvirt and your groups. |
| Windows: `doctor` reports `tcg` instead of `whpx` | Enable **Windows Hypervisor Platform** (see Installation) and reboot. TCG works, but it's slow. |
| Windows: QEMU exits with `WHPX: Unexpected VP exit code 4` | Don't force a CPU model. Remove `-cpu` from `[qemu].extra_args`. YEMU already uses the default CPU model under WHPX. |
| qemu backend: guest agent timeout during `vm create` | Look at `<VM storage>/qemu/<name>/console.log` to follow cloud-init, and at `qemu.log` for QEMU errors. |

## Project layout

```
yemu/
  app.py             GTK4 / libadwaita application
  cli.py             `yemu` command-line interface
  paths.py           per-user data/config/cache locations
  config.py          config.toml loading and defaults
  core/              pipeline, VM backends (libvirt, qemu, mock), guest agent, YARA, parsing, scoring, provisioning
  storage/           SQLite access layer and report writer
  ui/                GTK widgets and the VM-preparation window
  rules/default.yar  built-in YARA rules
scripts/setup_windows.ps1  one-shot Windows setup (QEMU, WHPX check, venv)
scripts/setup_linux.sh     one-shot Linux / WSL2 setup
scripts/prepare_vm.sh      shell version of VM preparation (libvirt)
tests/               pytest suites
main.py              compatibility launcher for the GUI
```
