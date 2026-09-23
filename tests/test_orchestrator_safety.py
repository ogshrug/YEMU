import asyncio
import json

import pytest
import pytest_asyncio

from yemu import config as yemu_config
from yemu.core import heuristics
from yemu.core.orchestrator import Orchestrator
from yemu.core.vm_manager import MockVMManager
from yemu.storage.db import Database


class RecordingMock(MockVMManager):
    """Mock backend that records every guest command and can be told to misbehave."""

    def __init__(self, fail_revert=False, hang_exec=False, listing=None):
        super().__init__()
        self.commands = []
        self.stopped = 0
        self.fail_revert = fail_revert
        self.hang_exec = hang_exec
        self.listing = listing

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        if self.fail_revert:
            raise RuntimeError("snapshot missing")
        return True

    async def stop_vm(self, vm_name):
        self.stopped += 1
        return True

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        self.commands.append(command)
        if self.hang_exec and "strace -ff" in command:
            await asyncio.sleep(3600)
        if self.listing is not None and command.startswith("ls -1 "):
            return self.listing
        return await super().run_command(vm_name, command, shell)


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(tmp_path / "t.db")
    await database.connect()
    yield database
    await database.close()


def _cfg(**analysis):
    cfg = yemu_config.load()
    cfg["analysis"].update(execution_wait=0, **analysis)
    return cfg


def _sample(tmp_path, data=b"#!/bin/sh\necho hi\n"):
    p = tmp_path / "my sample;$(reboot).sh"
    p.write_bytes(data)
    return str(p)


@pytest.mark.asyncio
async def test_failed_revert_aborts_before_execution(db, tmp_path):
    vm = RecordingMock(fail_revert=True)
    aid = await Orchestrator(db, vm_manager=vm, config=_cfg()).run_analysis(_sample(tmp_path), guest_os="mock-ubuntu")
    details = await db.get_analysis_details(aid)
    assert details["status"] == "failed" and "revert" in details["error"]
    assert not any("strace" in c for c in vm.commands), "sample must not run on an unreverted VM"
    assert vm.stopped >= 1


@pytest.mark.asyncio
async def test_oversized_sample_rejected(db, tmp_path):
    vm = RecordingMock()
    big = _sample(tmp_path, b"x" * (2 * 1024 * 1024))
    assert await Orchestrator(db, vm_manager=vm, config=_cfg(max_sample_mb=1)).run_analysis(big) is None
    assert vm.commands == []


@pytest.mark.asyncio
async def test_timeout_marks_status_and_powers_off(db, tmp_path):
    vm = RecordingMock(hang_exec=True)
    aid = await Orchestrator(db, vm_manager=vm, config=_cfg(timeout=1)).run_analysis(
        _sample(tmp_path), guest_os="mock-ubuntu"
    )
    details = await db.get_analysis_details(aid)
    assert details["status"] == "timeout"
    assert vm.stopped >= 1


@pytest.mark.asyncio
async def test_guest_paths_are_quoted_and_listing_is_filtered(db, tmp_path):
    hostile = "strace.1234\nstrace.1;rm -rf /\n$(id)\nstrace.99x"
    vm = RecordingMock(listing=hostile)
    aid = await Orchestrator(db, vm_manager=vm, config=_cfg()).run_analysis(_sample(tmp_path), guest_os="mock-ubuntu")
    cats = [c for c in vm.commands if c.startswith("cat ") and "strace." in c]
    assert len(cats) == 1 and cats[0].rstrip("'").endswith("/strace.1234")
    assert not any("rm -rf" in c or "$(id)" in c for c in vm.commands)
    # the sample's odd file name is sanitised in the guest path
    assert not any("$(reboot)" in c for c in vm.commands)
    assert (await db.get_analysis_details(aid))["status"] == "completed"


@pytest.mark.asyncio
async def test_completed_run_records_scoring_reasons(db, tmp_path):
    aid = await Orchestrator(db, vm_manager=RecordingMock(), config=_cfg()).run_analysis(
        _sample(tmp_path), guest_os="mock-ubuntu"
    )
    details = await db.get_analysis_details(aid)
    assert details["status"] == "completed"
    scoring = json.loads(details["scoring"])
    kinds = {r["kind"] for r in scoring["findings"]["reasons"]}
    assert "persistence" in kinds  # mock writes /etc/cron.d/updater
    assert scoring["findings"]["persistence_detected"] is True


def test_heuristics():
    events = [
        {"type": "file", "action": "open", "path": "/usr/lib/libc.so.6", "raw": "openat(..., O_RDONLY)"},
        {"type": "file", "action": "open", "path": "/etc/shadow", "raw": "openat(..., O_RDONLY)"},
        {"type": "file", "action": "open", "path": "/root/.bashrc", "raw": "openat(..., O_WRONLY|O_APPEND)"},
        {"type": "process", "action": "execute", "path": "/usr/bin/wget", "cmdline": "wget http://x", "ppid": "1"},
        {"type": "network", "action": "connect", "dst_ip": "8.8.8.8", "dst_port": "53", "process_name": "x"},
        {"type": "network", "action": "connect", "dst_ip": "127.0.0.53", "dst_port": "53", "process_name": "x"},
        {"type": "network", "action": "connect", "dst_ip": "192.168.1.5", "dst_port": "80", "process_name": "x"},
    ]
    f = heuristics.analyse(events)
    assert f["network_alerts"] == 1  # only the public address counts
    assert f["persistence_detected"] is True
    assert f["syscall_alerts"] == 3  # shadow, bashrc, wget; a plain library open is not suspicious
    assert heuristics.analyse([e for e in events[:1]])["syscall_alerts"] == 0
