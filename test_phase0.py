import os
import sys
import threading
import pytest
from unittest.mock import MagicMock

if 'libvirt' not in sys.modules:
    sys.modules['libvirt'] = MagicMock()

from core.async_runner import AsyncRunner
from core.orchestrator import Orchestrator
from core.vm_manager import MockVMManager
from storage.db import Database


@pytest.mark.asyncio
async def test_successful_run_persists_score_and_verdict(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # orchestrator writes reports relative to CWD
    db = Database(str(tmp_path / "yemu.db"))
    await db.connect()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"dummy")
    messages = []
    try:
        orch = Orchestrator(db, vm_manager=MockVMManager(), ui_callback=lambda m, s="INFO": messages.append(m))
        analysis_id = await orch.run_analysis(str(sample), guest_os="mock-ubuntu", snapshot_name="clean-baseline")
        details = await db.get_analysis_details(analysis_id)
        assert not any("Threat scoring failed" in m for m in messages), messages
        assert details['verdict'] in ("clean", "suspicious", "malicious")
        # MockVMManager returns two in-guest YARA memory hits
        assert details['threat_score'] >= 40
    finally:
        await db.close()


def test_async_runner_shares_db_connection_across_threads(tmp_path):
    runner = AsyncRunner()
    db = Database(str(tmp_path / "yemu.db"))
    try:
        runner.run(db.connect(), timeout=10)
        results, errors = [], []

        def worker():
            try:
                results.append(runner.run(db.get_recent_analyses(), timeout=10))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(results) == 5
    finally:
        runner.run(db.close(), timeout=10)
        runner.stop()


def test_async_runner_on_done_reports_errors():
    runner = AsyncRunner()
    done = threading.Event()
    seen = {}

    async def boom():
        raise ValueError("nope")

    def on_done(result, error):
        seen['error'] = error
        done.set()

    try:
        runner.submit(boom(), on_done=on_done)
        assert done.wait(5)
        assert isinstance(seen['error'], ValueError)
    finally:
        runner.stop()
