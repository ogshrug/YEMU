"""
Headless entry point; works on Linux and Windows.

    yemu vm create ubuntu-clean            # build an isolated analysis VM (qemu or libvirt)
    yemu analyze sample.bin                # detonate a sample
    yemu analyze sample.bin --backend mock --json
    yemu reports / yemu report 3
    yemu sync-rules
    yemu doctor
"""
import argparse
import asyncio
import json
import logging
import os
import platform
import shutil
import sys

from yemu import __version__
from yemu import config as yemu_config
from yemu import paths
from yemu.core.vm_backend import BACKENDS, create_backend

SEVERITY_PREFIX = {"INFO": "[*]", "WARN": "[!]", "CRITICAL": "[X]"}


def _printer(quiet=False):
    def ui_callback(msg, severity="INFO"):
        if quiet and severity == "INFO":
            return
        print(f"{SEVERITY_PREFIX.get(severity, '[*]')} {msg}", file=sys.stderr, flush=True)
    return ui_callback


def _json_default(value):
    return str(value)


async def _with_db(fn):
    from yemu.storage.db import Database
    db = Database()
    await db.connect()
    try:
        return await fn(db)
    finally:
        await db.close()


def cmd_gui(args, cfg):
    from yemu.app import main as gui_main
    return gui_main([sys.argv[0]])


def cmd_analyze(args, cfg):
    from yemu.core.orchestrator import Orchestrator

    if not os.path.isfile(args.sample):
        print(f"Sample not found: {args.sample}", file=sys.stderr)
        return 2

    callback = _printer(quiet=args.json)
    backend = create_backend(args.backend or cfg["vm"]["backend"], ui_callback=callback, config=cfg)

    async def run(db):
        orch = Orchestrator(db, vm_manager=backend, ui_callback=callback, config=cfg)
        analysis_id = await orch.run_analysis(
            os.path.abspath(args.sample),
            guest_os=args.vm or cfg["vm"]["default_vm"],
            snapshot_name=args.snapshot or cfg["vm"]["default_snapshot"],
            run_pcap=args.pcap,
        )
        return analysis_id, await db.get_analysis_details(analysis_id) if analysis_id else None

    analysis_id, details = asyncio.run(_with_db(run))
    if not details:
        print("Analysis failed to start; see messages above.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(details, indent=2, default=_json_default))
    else:
        print(f"\nAnalysis #{analysis_id}: {details['filename']}")
        print(f"  status:  {details.get('status')}" + (f"  ({details['error']})" if details.get("error") else ""))
        print(f"  verdict: {details['verdict'] or 'unknown'}")
        print(f"  score:   {details['threat_score'] or 0}/100")
        print(f"  report:  {paths.reports_dir() / f'report_{analysis_id}.json'}")
    # exit codes for pipelines: 3 = malicious, 4 = analysis failed/timed out (verdict incomplete)
    if details.get("status") in ("failed", "timeout"):
        return 4
    return 3 if details.get("verdict") == "malicious" else 0


def cmd_reports(args, cfg):
    rows = asyncio.run(_with_db(lambda db: db.get_recent_analyses(limit=args.limit)))
    if args.json:
        print(json.dumps(rows, indent=2, default=_json_default))
        return 0
    if not rows:
        print("No analyses yet.")
        return 0
    print(f"{'ID':>4}  {'VERDICT':<11} {'SCORE':>5}  {'STATUS':<11} {'STARTED':<26} FILE")
    for r in rows:
        print(f"{r['id']:>4}  {(r['verdict'] or 'unknown'):<11} {(r['threat_score'] or 0):>5}  "
              f"{(r.get('status') or '-'):<11} {str(r['started_at'] or ''):<26} {r['filename']}")
    return 0


def cmd_report(args, cfg):
    async def fetch(db):
        details = await db.get_analysis_details(args.id)
        events = await db.get_analysis_events(args.id) if details else []
        return details, events

    details, events = asyncio.run(_with_db(fetch))
    if not details:
        print(f"Analysis #{args.id} not found.", file=sys.stderr)
        return 1
    for key in ("yara_matches", "report_json", "scoring"):
        if isinstance(details.get(key), str):
            try:
                details[key] = json.loads(details[key])
            except json.JSONDecodeError:
                pass
    details["events"] = events
    print(json.dumps(details, indent=2, default=_json_default))
    return 0


def _backend(args, cfg):
    return create_backend(getattr(args, "backend", None) or cfg["vm"]["backend"], ui_callback=_printer(), config=cfg)


def cmd_list_vms(args, cfg):
    backend = _backend(args, cfg)
    vms = sorted(backend.list_vms())
    if not vms:
        print(f"No VMs on the {backend.name} backend. Create one with: yemu vm create <name>")
    for vm in vms:
        snaps = backend.list_snapshots(vm)
        print(f"{vm}  [{backend.name}]  snapshots: {', '.join(snaps) or '-'}")
    return 0


def cmd_vm_create(args, cfg):
    from yemu.core.provisioning import ProvisioningError, provision_vm

    backend = _backend(args, cfg)
    if backend.name == "mock":
        print("No real VM backend available (install QEMU, or libvirt on Linux). See `yemu doctor`.", file=sys.stderr)
        return 2

    last = {"pct": -1}

    def progress(msg, fraction):
        if msg:
            print(f"[*] {msg}", file=sys.stderr, flush=True)
        elif fraction is not None and int(fraction * 100) != last["pct"]:
            last["pct"] = int(fraction * 100)
            print(f"\r    {last['pct']:3d}%", end="", file=sys.stderr, flush=True)

    try:
        password = asyncio.run(provision_vm(
            backend, args.name, distro=args.distro, ram_mb=args.ram, cpus=args.cpus, disk_gb=args.disk,
            analysis_network=cfg["network"]["name"], snapshot_name=cfg["vm"]["default_snapshot"],
            progress=progress))
    except (ProvisioningError, RuntimeError, OSError) as e:
        print(f"\n[X] VM preparation failed: {e}", file=sys.stderr)
        return 1
    print(f"\nVM '{args.name}' is ready on the {backend.name} backend.")
    print(f"Guest console password: {password}")
    if args.name != cfg["vm"]["default_vm"]:
        print(f'Tip: set default_vm = "{args.name}" under [vm] in {paths.config_file()}')
    return 0


def cmd_vm_start(args, cfg):
    backend = _backend(args, cfg)
    ok = asyncio.run(backend.start_vm(args.name))
    if ok and args.console:
        asyncio.run(backend.open_gui(args.name))
    print(f"{args.name}: {'started' if ok else 'failed to start'}")
    return 0 if ok else 1


def cmd_vm_stop(args, cfg):
    ok = asyncio.run(_backend(args, cfg).stop_vm(args.name))
    print(f"{args.name}: {'stopped' if ok else 'failed to stop'}")
    return 0 if ok else 1


def cmd_vm_delete(args, cfg):
    backend = _backend(args, cfg)
    if not hasattr(backend, "delete_vm"):
        print(f"Deleting VMs is not supported on the {backend.name} backend; use virsh/virt-manager.", file=sys.stderr)
        return 2
    if not args.yes:
        print(f"This deletes VM '{args.name}' and its disk. Re-run with --yes to confirm.", file=sys.stderr)
        return 2
    asyncio.run(backend.delete_vm(args.name))
    print(f"{args.name}: deleted")
    return 0


def cmd_sync_rules(args, cfg):
    from yemu.core.yara_sync import RuleSyncError, YaraRuleSync

    def progress(current, total, filename):
        print(f"\r[{current}/{total}] {filename[:60]:<60}", end="", file=sys.stderr, flush=True)

    try:
        sync = YaraRuleSync(repo_url=args.repo or cfg["rules"]["repo_url"],
                            branch=args.branch or cfg["rules"]["branch"],
                            ref=args.ref if args.ref is not None else cfg["rules"]["ref"],
                            max_download_mb=cfg["rules"]["max_download_mb"])
        manifest = sync.sync(progress_callback=progress)
    except (RuleSyncError, OSError) as e:
        print(f"\nRule sync failed: {e}", file=sys.stderr)
        return 1
    print(file=sys.stderr)
    print(f"Synced into {paths.synced_rules_dir()}")
    if isinstance(manifest, dict):
        print(json.dumps({k: v for k, v in manifest.items() if not isinstance(v, (list, dict))}, indent=2))
    return 0


def cmd_paths(args, cfg):
    for name, value in paths.summary().items():
        print(f"{name:<14} {value}")
    return 0


def cmd_config(args, cfg):
    if args.init:
        path, written = yemu_config.write_template(overwrite=args.force)
        print(f"{'Wrote' if written else 'Already exists (use --force to overwrite)'}: {path}")
        return 0
    print(f"# effective config (file: {paths.config_file()})")
    print(json.dumps(cfg, indent=2))
    return 0


def _check(label, ok, detail=""):
    print(f"  [{'ok' if ok else '--'}] {label}{': ' + detail if detail else ''}")
    return ok


def cmd_doctor(args, cfg):
    print(f"YEMU {__version__} on {platform.system()} {platform.release()} / Python {platform.python_version()}")
    print("\nCore (all platforms):")
    _check("Python >= 3.10", sys.version_info >= (3, 10), platform.python_version())
    for mod in ("yara", "aiosqlite", "reportlab", "requests", "scapy", "platformdirs"):
        try:
            __import__(mod)
            _check(mod, True)
        except Exception as e:
            _check(mod, False, str(e).splitlines()[0])
    _check("built-in rules", paths.BUILTIN_RULES_FILE.is_file(), str(paths.BUILTIN_RULES_FILE))

    print("\nDesktop app:")
    try:
        import PySide6
        _check("PySide6 (Qt)", True, PySide6.__version__)
    except Exception as e:
        _check("PySide6 (Qt)", False, f"{type(e).__name__}: pip install \"yemu[gui]\"")

    print("\nVM backend (qemu, works on Windows and Linux):")
    from yemu.core.qemu_backend import QemuBackend
    qemu = QemuBackend(config=cfg)
    _check("qemu-system-x86_64", bool(qemu.qemu_system), qemu.qemu_system or "not found (install QEMU or set [qemu].bin_dir)")
    _check("qemu-img", bool(qemu.qemu_img), qemu.qemu_img or "not found")
    if qemu.qemu_system:
        accel = qemu.accel
        _check("hardware acceleration", accel != "tcg",
               accel if accel != "tcg" else "tcg only: enable Windows Hypervisor Platform (Windows) or /dev/kvm access (Linux)")
    try:
        import pycdlib  # noqa: F401
        _check("cloud-init ISO builder", True, "pycdlib")
    except ImportError:
        from yemu.core.vm_provisioner import VMProvisioner
        tool = VMProvisioner._find_mkisofs()
        _check("cloud-init ISO builder", bool(tool), tool or "install pycdlib or genisoimage")

    print("\nVM backend (libvirt, Linux only):")
    if os.name != "posix":
        print("  Not applicable on Windows. Use the qemu backend above, or run YEMU inside WSL2.")
    else:
        if _is_wsl():
            print("  Running inside WSL2.")
            _check("systemd (needed by libvirtd)", os.path.isdir("/run/systemd/system"),
                   "add [boot] systemd=true to /etc/wsl.conf, then run `wsl --shutdown`")
        _check("/dev/kvm", os.path.exists("/dev/kvm"))
        for tool in ("virsh", "qemu-img", "virt-copy-in", "virt-viewer"):
            _check(tool, shutil.which(tool) is not None)
        try:
            import libvirt  # noqa: F401
            _check("libvirt-python", True)
        except ImportError:
            _check("libvirt-python", False)
        from yemu.core.vm_manager import VMManager
        try:
            VMManager()._get_conn()
            _check("libvirt connection", True, "connected")
        except Exception as e:
            _check("libvirt connection", False, str(e).splitlines()[0])

    chosen = create_backend(cfg["vm"]["backend"], config=cfg)
    print(f"\nSelected backend ([vm].backend = {cfg['vm']['backend']}): {chosen.name}")
    return 0


def _is_wsl():
    try:
        with open("/proc/version", encoding="utf-8") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def build_parser():
    parser = argparse.ArgumentParser(prog="yemu", description="YEMU malware analysis sandbox")
    parser.add_argument("--version", action="version", version=f"yemu {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("gui", help="launch the desktop app").set_defaults(func=cmd_gui)

    p = sub.add_parser("analyze", help="detonate a sample and print the verdict")
    p.add_argument("sample")
    p.add_argument("--vm", help="libvirt domain (default from config)")
    p.add_argument("--snapshot", help="snapshot to revert to (default from config)")
    p.add_argument("--pcap", action="store_true", help="capture guest traffic")
    p.add_argument("--backend", choices=BACKENDS, help="override [vm].backend")
    p.add_argument("--json", action="store_true", help="print the analysis record as JSON")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("reports", help="list recent analyses")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_reports)

    p = sub.add_parser("report", help="print one analysis with its events as JSON")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("list-vms", help="list VMs and snapshots (same as `yemu vm list`)")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_list_vms)

    vm = sub.add_parser("vm", help="create and manage analysis VMs")
    vm_sub = vm.add_subparsers(dest="vm_command", required=True)
    p = vm_sub.add_parser("list", help="list VMs and snapshots")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_list_vms)
    p = vm_sub.add_parser("create", help="download a cloud image and build an isolated analysis VM")
    p.add_argument("name")
    p.add_argument("--distro", choices=("ubuntu", "debian", "windows"), default="ubuntu")
    p.add_argument("--ram", type=int, default=2048, help="MiB")
    p.add_argument("--cpus", type=int, default=2)
    p.add_argument("--disk", type=int, default=20, help="GiB")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_vm_create)
    p = vm_sub.add_parser("start", help="boot a VM")
    p.add_argument("name")
    p.add_argument("--console", action="store_true", help="open a viewer on the VM display")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_vm_start)
    p = vm_sub.add_parser("stop", help="power a VM off")
    p.add_argument("name")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_vm_stop)
    p = vm_sub.add_parser("delete", help="delete a VM and its disk (qemu backend)")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_vm_delete)

    p = sub.add_parser("sync-rules", help="download YARA rules from GitHub")
    p.add_argument("--repo")
    p.add_argument("--branch")
    p.add_argument("--ref", help="pin a commit SHA or tag (overrides [rules].ref)")
    p.set_defaults(func=cmd_sync_rules)

    sub.add_parser("paths", help="show where YEMU stores data").set_defaults(func=cmd_paths)

    p = sub.add_parser("config", help="show effective config, or create a template")
    p.add_argument("--init", action="store_true", help="write a commented config.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_config)

    sub.add_parser("doctor", help="check dependencies for this host").set_defaults(func=cmd_doctor)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    from yemu.logging_setup import setup_logging
    setup_logging(console_level=logging.DEBUG if args.verbose else logging.WARNING,
                  file_level=logging.DEBUG if args.verbose else logging.INFO)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args, yemu_config.load())


if __name__ == "__main__":
    sys.exit(main())
