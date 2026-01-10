import json, uuid, time, threading

class ComplianceAuditor:
    """Independent Forensic Auditor with Thread-Safe Logging."""
    def __init__(self):
        self.log_lock = threading.Lock()
        self.risk_keywords = ["withdraw", "transfer", "pay", "spend", "move", "liquidate"]
        self.legal_db = {
            "HIGH": "EU AI Act Article 14: Mandatory human oversight for high-risk financial autonomy.",
            "STD": "SOC2 CC7.2: Continuous activity monitoring."
        }

    def verify_and_audit(self, log):
        # 1. Independent Logic Verification (Zero-Trust)
        amount = log.get("amount", 0)
        is_financial = any(w in log.get("task", "").lower() for w in self.risk_keywords)
        
        audit_verdict = "PASSED"
        if (amount >= 1000 or is_financial) and log.get("decision") == "ALLOW":
            audit_verdict = "SECURITY_MISMATCH_ALERT"

        # 2. RAG Citation
        risk = "HIGH" if amount >= 1000 else "STD"
        report = {
            "audit_id": f"AUD-{uuid.uuid4().hex[:6].upper()}",
            "verdict": audit_verdict,
            "law": self.legal_db[risk],
            "agent": log.get("sender"),
            "timestamp": time.strftime("%H:%M:%S")
        }

        with self.log_lock:
            with open("forensic_audit.json", "a") as f:
                f.write(json.dumps(report) + "\n")
        return report
