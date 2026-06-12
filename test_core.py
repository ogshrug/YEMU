import asyncio
from core.threat_scorer import ThreatScorer
from core.yara_engine import YaraEngine
import os

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
    # Create a temp file to scan
    with open("test_sample.txt", "w") as f:
        f.write("This is a test sample with encrypt and decrypt keywords.")

    engine = YaraEngine(rules_path="rules/default.yar")
    matches = engine.scan_file("test_sample.txt")

    assert any("Ransomware_Heuristic" in m for m in matches)
    os.remove("test_sample.txt")
    print("YaraEngine tests passed!")

if __name__ == "__main__":
    test_threat_scorer()
    test_yara_engine()
