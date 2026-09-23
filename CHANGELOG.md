# Changelog

## 0.6.0 (2026-09-24)

The production-readiness release: YEMU runs natively on Windows and Linux, has a new desktop app, and ships as installable packages.

### Platforms and packaging
- Native Windows support through a standalone QEMU backend with WHPX acceleration. It also works on Linux with KVM and falls back to TCG emulation.
- A Windows installer (per-user or all-users, optional PATH entry), a portable Windows zip, a Linux bundle tarball with `install.sh`, and a Python wheel and sdist.
- A release workflow that builds everything and publishes a GitHub release on `v*` tags.
- Setup scripts for Windows (`scripts/setup_windows.ps1`) and Linux or WSL2 (`scripts/setup_linux.sh`).

### Desktop app
- Rewritten in PySide6 (Qt). The pages are Analyze (drag and drop, live stage tracker), History, Report (score gauge, "Why this verdict", process tree, YARA, behaviour timeline, network IOCs, PDF/JSON export), VMs, YARA rules (highlighting editor, validation, sync) and Settings.
- Light and dark themes, and a new app icon.

### Command line
- `yemu analyze | reports | report | vm create/start/stop/delete/list | sync-rules | paths | config | doctor | gui`.
- Exit codes for pipelines: 3 means malicious, 4 means the analysis failed or timed out.

### Analysis and scoring
- The in-guest memory scan now targets the sample's own processes by PID. Before, it scanned all of `/proc` and always timed out.
- Behaviour heuristics now explain their findings: sensitive-file reads, persistence writes, downloader and shell execs, deletions, and connections to public IPs. Only activity from the sample's own process tree is scored. **Scores differ from 0.4 and earlier.**
- Every analysis records a status (`completed`, `failed`, `timeout` or `manual`) and the error, if any.

### Security
- The analysis network is isolated by default. NAT is used only while provisioning.
- A sample is never run on a VM whose snapshot revert failed.
- Every analysis has a hard time limit, size limits and a guaranteed power-off.
- Guest paths are random per run and shell-quoted, and data coming back from the guest is validated.
- YARA rule sync is pinned to a commit and size-capped. It is protected against zip-slip (a path-traversal bug existed before this release) and swaps rule sets atomically.
- Each VM gets a random guest password, and SSH password login is disabled.
- Added a threat model and a security policy.

### Reliability
- Versioned SQLite migrations. Databases created by older versions are upgraded automatically.
- A single event loop owns the database connection, which fixes intermittent cross-thread failures.
- Fixed a scoring crash that meant successful runs never saved a verdict.
- The built-in YARA rules are now always loaded.
- A rotating log file at `<data>/logs/yemu.log`.
- Per-user data, config and cache folders on each OS, plus a TOML config file.

### Development
- Code moved into the `yemu` package, with a `pyproject.toml` and a VM backend interface.
- ruff and mypy, and CI on Ubuntu and Windows with Python 3.10 and 3.12. The GUI is tested off-screen.

## 0.1.0 – 0.4.x

Pre-release development of the original GTK4, Linux-only sandbox.
