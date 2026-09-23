class ThreatScorer:
    """
    Computes a 0-100 threat score based on findings.
    Weights and verdict thresholds come from the [scoring] config section.
    """
    DEFAULT_WEIGHTS = {
        "yara_match": 40,
        "yara_many_bonus": 10,
        "yara_many_threshold": 3,
        "suspicious_syscall_each": 5,
        "suspicious_syscall": 20,
        "network_c2": 30,
        "file_persistence": 10,
        "suspicious_threshold": 30,
        "malicious_threshold": 70,
    }

    def __init__(self, weights=None):
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}

    def compute(self, findings):
        w = self.weights
        score = 0

        # findings is a dict like:
        # {"yara_count": 2, "network_alerts": 1, "persistence_detected": False, "syscall_alerts": 5}

        if findings.get("yara_count", 0) > 0:
            score += w["yara_match"]
            if findings.get("yara_count", 0) > w["yara_many_threshold"]:
                score += w["yara_many_bonus"]  # Extra penalty

        if findings.get("network_alerts", 0) > 0:
            score += w["network_c2"]

        if findings.get("persistence_detected"):
            score += w["file_persistence"]

        if findings.get("syscall_alerts", 0) > 0:
            score += min(w["suspicious_syscall"], findings["syscall_alerts"] * w["suspicious_syscall_each"])

        return min(100, score)

    def get_verdict(self, score):
        if score < self.weights["suspicious_threshold"]: return "clean"
        if score < self.weights["malicious_threshold"]: return "suspicious"
        return "malicious"
