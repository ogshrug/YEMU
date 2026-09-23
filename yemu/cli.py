"""
Headless entry point. Works on any host; VM-backed commands need the libvirt
backend (Linux + KVM), everything else (mock analysis, reports, rules, config)
runs on Windows too.

    yemu analyze sample.bin --vm ubuntu-clean
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
    backend = create_backend(args.backend or cfg["vm"]["backend"], ui_callback=callback)

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
        print(f"  verdict: {details['verdict'] or 'unknown'}")
        print(f"  score:   {details['threat_score'] or 0}/100")
        print(f"  report:  {paths.reports_dir() / f'report_{analysis_id}.json'}")
    # Non-zero exit for malicious samples makes the CLI usable in pipelines
    return 3 if details.get("verdict") == "malicious" else 0


def cmd_reports(args, cfg):
    rows = asyncio.run(_with_db(lambda db: db.get_recent_analyses(limit=args.limit)))
    if args.json:
        print(json.dumps(rows, indent=2, default=_json_default))
        return 0
    if not rows:
        print("No analyses yet.")
        return 0
    print(f"{'ID':>4}  {'VERDICT':<11} {'SCORE':>5}  {'STARTED':<26} FILE")
    for r in rows:
        print(f"{r['id']:>4}  {(r['verdict'] or 'unknown'):<11} {(r['threat_score'] or 0):>5}  "
              f"{str(r['started_at'] or ''):<26} {r['filename']}")
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
    for key in ("yara_matches", "report_json"):
        if isinstance(details.get(key), str):
            try:
                details[key] = json.loads(details[key])
            except json.JSONDecodeError:
                pass
    details["events"] = events
    print(json.dumps(details, indent=2, default=_json_default))
    return 0


def cmd_list_vms(args, cfg):
    backend = create_backend(args.backend or cfg["vm"]["backend"], ui_callback=_printer())
    for vm in sorted(backend.list_vms()):
        snaps = backend.list_snapshots(vm)
        print(f"{vm}  [{backend.name}]  snapshots: {', '.join(snaps) or '-'}")
    return 0


def cmd_sync_rules(args, cfg):
    from yemu.core.yara_sync import YaraRuleSync

    def progress(current, total, filename):
        print(f"\r[{current}/{total}] {filename[:60]:<60}", end="", file=sys.stderr, flush=True)

    sync = YaraRuleSync(repo_url=args.repo or cfg["rules"]["repo_url"],
                        branch=args.branch or cfg["rules"]["branch"])
    manifest = sync.sync(progress_callback=progress)
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

    print("\nGUI:")
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Gtk, Adw  # noqa: F401
        _check("GTK 4 + libadwaita", True)
    except Exception as e:
        _check("GTK 4 + libadwaita", False, f"{type(e).__name__} (GUI needs Linux or WSL2)")

    print("\nVM backend (libvirt):")
    if os.name != "posix":
        print("  libvirt backend is Linux-only. On Windows, run YEMU inside WSL2 or use --backend mock.")
    else:
        _check("/dev/kvm", os.path.exists("/dev/kvm"))
        for tool in ("virsh", "qemu-img", "virt-copy-in", "virt-viewer"):
            _check(tool, shutil.which(tool) is not None)
        try:
            import libvirt  # noqa: F401
            _check("libvirt-python", True)
        except ImportError:
            _check("libvirt-python", False)
        backend = create_backend("auto")
        _check("libvirt connection", backend.name == "libvirt",
               "connected" if backend.name == "libvirt" else "falling back to mock")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="yemu", description="YEMU malware analysis sandbox")
    parser.add_argument("--version", action="version", version=f"yemu {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("gui", help="launch the desktop app (Linux / WSL2)").set_defaults(func=cmd_gui)

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

    p = sub.add_parser("list-vms", help="list VMs and snapshots")
    p.add_argument("--backend", choices=BACKENDS)
    p.set_defaults(func=cmd_list_vms)

    p = sub.add_parser("sync-rules", help="download YARA rules from GitHub")
    p.add_argument("--repo")
    p.add_argument("--branch")
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
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="[%(levelname)s] %(name)s: %(message)s")
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args, yemu_config.load())


if __name__ == "__main__":
    sys.exit(main())
