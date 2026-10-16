# Changelog

## 0.7.5 (2026-10-16)

### Performance
- The YARA rules are compiled once per analysis instead of three times. Files are only checked one by one when the full set fails to compile.
- Strace and PCAP parsing, scoring, sample hashing and rule loading run in worker threads, so they no longer stall the app while an analysis runs, and the analysis timeout fires on time. Captures are read packet by packet instead of all at once.
- Large reports open without freezing the window. The Raw JSON tab is filled when it's first opened and leaves out the `behaviour` list, which repeats `events` (Export JSON still includes it).

## 0.7.1 (2026-10-16)

### Look and feel
- A new "Lab bench" theme for the desktop app: warm paper and graphite neutrals with a petrol-teal accent, in light and dark. The accent never overlaps the green, amber and red verdict colours.
- Every colour in the app now comes from the theme: stage tracker, run and VM states, the drop zone, verdict badges, the YARA editor highlighting and the backend status dot all follow light and dark.
- One corner radius scale, visible keyboard focus on inputs, buttons, tables and checkboxes, and the selected page in the sidebar is marked with an accent bar. The sidebar shield and page icons follow a live theme switch.

### YARA rules
- Several rule sources at once: `[rules].sources` is a list of `[[rules.sources]]` tables (YARA Forge packages and GitHub repositories), each synced into its own rule set and all loaded for every analysis.
- Configs with the old single `source`/`package`/`repo_url`/`branch`/`ref` keys under `[rules]` are converted on load, and the next save writes the new format.
- One failing source no longer blocks the rest: its previous set stays in place, and `yemu sync-rules` / `yemu update rules` report it and exit with 1. A full sync removes YEMU-managed sets that are no longer configured.
- `yemu sync-rules --package`/`--repo` syncs one extra set; `--branch` or `--ref` on their own are now an error. `yemu update check` lists every source with its synced version.
- **Settings → Updates** has a source list with **Add source** and **Remove**; the YARA rules page shows each source's synced version and date.

### Reliability
- A `config.toml` that can't be parsed, or has a value of the wrong type (`timeout = "900"`, `true` for a number) or an unknown choice (`backend`, `accel`, `theme`, rule `source`), is reported as a config error instead of being silently replaced by defaults. The CLI prints one `Config error:` line and exits 2 (`yemu paths` and `yemu config --init` still work); the desktop app shows the error and exits without touching the file.
- CLI crashes print one `Error:` line pointing at `yemu.log`, which has the traceback (`-v` also prints it). Ctrl+C prints `Interrupted.` and exits 130.
- Unexpected errors in the desktop app are logged and shown in a dialog instead of disappearing.
- Analyses left `running` by a YEMU that was closed or killed mid-run are marked `interrupted` when the database is next opened.
- The Analyze page says why a sample can't be used (a folder, a missing file, a file over the size limit, or a file that can't be read) and keeps Start disabled.
- A failure to close the database on exit is logged.

## 0.7.0 (2026-09-29)

### YARA rules
- The default rule source is now **YARA Forge core**, a curated weekly bundle of about 5,100 rules from around 40 maintained repositories. The previous default, `Yara-Rules/rules`, hadn't changed since 2022. `extended` and `full` packages are available, and any GitHub rule repository can still be used.
- Rules update automatically in the background (every 7 days by default, configurable). New commands: `yemu update rules [--force]`. `yemu sync-rules --package`.
- A successful sync replaces earlier YEMU-downloaded rule sets, so switching sources doesn't leave stale rules loaded. Hand-written rules are kept.
- Synced rule sets are read-only in the editor. Very large bundles show a summary instead of freezing the UI.

### App updates
- The desktop app checks GitHub for new YEMU releases at startup (at most daily, can be turned off). The update offer matches how YEMU was installed: installer, portable zip, pip or Linux bundle.
- Downloads are verified against the release's `SHA256SUMS.txt` before anything is installed.
- New commands: `yemu update` and `yemu update app`. A new **Settings → Updates** section, and a **Check for updates now** button.

## 0.6.1 (2026-09-24)

- Licensed under the Apache License 2.0. `LICENSE` and `NOTICE` are included in the Python packages, the Windows installer (shown as the license page) and the portable and Linux bundles.
- Added `ROADMAP.md` with the planned work after 0.6.0.

No functional changes since 0.6.0.

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
