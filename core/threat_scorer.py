class ThreatScorer:
    """
    Computes a 0-100 threat score based on findings.
    """
    WEIGHTS = {
        "yara_match": 40,
        "suspicious_syscall": 20,
        "network_c2": 30,
        "file_persistence": 10
    }

    def compute(self, findings):
        score = 0

        # findings is a dict like:
        # {"yara_count": 2, "network_alerts": 1, "persistence_detected": False, "syscall_alerts": 5}

        if findings.get("yara_count", 0) > 0:
            score += self.WEIGHTS["yara_match"]
            if findings.get("yara_count", 0) > 3:
                score += 10 # Extra penalty

        if findings.get("network_alerts", 0) > 0:
            score += self.WEIGHTS["network_c2"]

        if findings.get("persistence_detected"):
            score += self.WEIGHTS["file_persistence"]

        if findings.get("syscall_alerts", 0) > 0:
            score += min(self.WEIGHTS["suspicious_syscall"], findings["syscall_alerts"] * 5)

        return min(100, score)

    def get_verdict(self, score):
        if score < 30: return "clean"
        if score < 70: return "suspicious"
        return "malicious"
