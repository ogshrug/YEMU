import asyncio
import pytest
from core.threat_scorer import ThreatScorer
from core.yara_engine import YaraEngine
import os
import shutil

def test_threat_scorer():
    scorer = ThreatScorer()

    # Test case 1: Low threat
    score1 = scorer.compute({"yara_count": 0, "network_alerts": 0})
    assert score1 == 0
    assert scorer.get_verdict(score1) == "clean"

    # Test case 2: High threat
    score2 = scorer.compute({"yara_count": 5, "network_alerts": 1, "persistence_detected": True})
    # 40 (yara) + 10 (extra yara) + 30 (network) + 10 (persistence) = 90
    assert score2 == 90
    assert scorer.get_verdict(score2) == "malicious"

    print("ThreatScorer tests passed!")

def test_yara_engine():
    # Create a temporary rules directory
    os.makedirs("test_rules", exist_ok=True)
    with open("test_rules/test.yar", "w") as f:
        f.write('rule test_rule { strings: $a = "encrypt" condition: $a }')

    # Create a temp file to scan
    with open("test_sample.txt", "w") as f:
        f.write("This is a test sample with encrypt and decrypt keywords.")

    engine = YaraEngine(rules_dir="test_rules")
    matches = engine.scan_file("test_sample.txt")

    print(f"Matches: {matches}")
    assert any(m["rule"] == "test_rule" for m in matches)

    os.remove("test_sample.txt")
    shutil.rmtree("test_rules")
    print("YaraEngine tests passed!")

import sys
from unittest.mock import MagicMock

# Mock libvirt and gi if not present for integration tests
if 'libvirt' not in sys.modules:
    sys.modules['libvirt'] = MagicMock()
if 'gi' not in sys.modules:
    sys.modules['gi'] = MagicMock()
    sys.modules['gi.repository'] = MagicMock()

@pytest.mark.asyncio
async def test_analysis_pipeline_resilience():
    from core.orchestrator import Orchestrator
    from storage.db import Database

    class FailingVMManager:
        def __init__(self, ui_callback=None):
            self.ui_callback = ui_callback
        async def verify_environment(self, *args, **kwargs): return True, "OK"
        async def revert_to_snapshot(self, *args, **kwargs): raise RuntimeError("Snapshot error")
        async def start_vm(self, *args, **kwargs): raise RuntimeError("Start error")
        async def inject_file(self, *args, **kwargs): raise RuntimeError("Inject error")
        async def run_command(self, *args, **kwargs): raise RuntimeError("Command error")
        async def stop_vm(self, *args, **kwargs): raise RuntimeError("Stop error")
        async def wait_for_guest_agent(self, *args, **kwargs): raise RuntimeError("Agent error")
        def list_vms(self): return ["test-vm"]
        def list_snapshots(self, vm): return ["test-snap"]

    # Setup temp DB
    db_path = "test_resilience.db"
    if os.path.exists(db_path): os.remove(db_path)
    db = Database(db_path)
    await db.connect()

    # Create dummy sample
    sample_path = "test_sample.bin"
    with open(sample_path, "wb") as f: f.write(b"dummy")

    vm_manager = FailingVMManager()
    orchestrator = Orchestrator(db, vm_manager=vm_manager)

    # This should NOT raise UnboundLocalError
    try:
        analysis_id = await orchestrator.run_analysis(sample_path, guest_os="test-vm", snapshot_name="test-snap")
        assert analysis_id is not None

        # Check if we can still get details even if it "failed"
        details = await db.get_analysis_details(analysis_id)
        assert details is not None
        assert details['filename'] == "test_sample.bin"
    finally:
        await db.close()
        if os.path.exists(db_path): os.remove(db_path)
        if os.path.exists(sample_path): os.remove(sample_path)

import pytest
if __name__ == "__main__":
    test_threat_scorer()
    test_yara_engine()
