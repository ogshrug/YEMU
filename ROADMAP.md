# YEMU roadmap

Planned work after 0.6.0, in priority order. Tick items off as they land and move them to the [changelog](CHANGELOG.md).

## 1. Close verification gaps

- [ ] **Install the Windows installer** (`YEMU-<version>-windows-x64-setup.exe`) on a clean Windows PC. Check the shortcuts, the PATH option, first launch and uninstall. So far it has only been built in CI.
- [ ] **Test on real Linux.** Check the libvirt backend, the Qt desktop app, `scripts/setup_linux.sh`, `scripts/prepare_vm.sh` and the tarball's `install.sh`. None of these have run since the Phase 1 refactor.
- [ ] **End-to-end test in CI with a real VM.** GitHub's Ubuntu runners expose `/dev/kvm`. A nightly job could build a minimal VM with `yemu vm create`, detonate a harmless sample and check the status, the YARA hits and the heuristics findings.

## 2. Trust and hardening

- [ ] **Code-sign the Windows builds** (installer and executables) so SmartScreen and Defender don't warn on first run.
- [ ] **Isolate host-side parsers.** Run PCAP parsing (scapy) and YARA output parsing in a separate low-privilege subprocess with time and memory limits. These are the largest remaining host attack surface in [docs/threat-model.md](docs/threat-model.md).
- [ ] **Supply-chain checks:** Dependabot, CodeQL code scanning, a pinned build lockfile, and an SBOM (CycloneDX) attached to each release.
- [ ] **Branch protection on `main`:** require a PR and green CI (lint, type checks and tests on both platforms).
- [ ] **Repository hygiene:** stop tracking `.idea/`, and find the editor tool that reformats Markdown files (tables flattened, backslashes stripped).

## 3. Better detection

- [ ] **Fake network services.** Simulate DNS, HTTP and HTTPS inside the isolated network (INetSim-style) so samples reveal their C2 requests and second-stage downloads instead of just failing to connect.
- [ ] **Disk diffing.** After each run, compare the guest disk against the `clean-baseline` snapshot to find dropped, modified and deleted files that strace doesn't attribute.
- [ ] **Static analysis:**
  - PE and ELF parsing: imports, sections, entropy, packer detection
  - string extraction
  - capa capability detection, mapped to MITRE ATT&CK techniques
- [ ] **Anti-evasion.** Make run length configurable per sample, simulate user activity, and reduce obvious VM and strace artefacts.
- [ ] **Scoring calibration.** Build a labelled benign and malicious corpus. Tune the weights in `[scoring]` and `core/heuristics.py` against it, then keep the corpus as a regression test so score changes are measured.

## 4. Bigger features

- [ ] **Windows guest analysis.** A Procmon, Sysmon or ETW collection pipeline and parser (`BehaviourMonitor.parse_procmon_csv` is a stub today), and Windows guest provisioning on the QEMU backend.
- [ ] **Parallel analyses.** A job queue plus linked-clone VMs (qcow2 overlays on one baseline), so several samples run at once.
- [ ] **Export and sharing.** HTML reports, plus STIX 2.1 and MISP export of IOCs and findings.
- [ ] **Optional online enrichment.** VirusTotal and MalwareBazaar hash lookups, off by default, with API keys stored in config.
