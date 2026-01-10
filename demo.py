from sdk import UAIP_Enterprise_SDK
from compliance import ComplianceAuditor
import time

SECRET_CODE = 987654321
auditor = ComplianceAuditor()

print("\n" + "="*60)
print("🛡️  UAIP + AGENTGUARD: SECURE ECONOMY DEMO")
print("="*60)

print("\n[STEP 1] INITIALIZING ENTERPRISE IDENTITIES...")
msft_agent = UAIP_Enterprise_SDK("Azure_Bot", "Microsoft", SECRET_CODE)

# SCENARIO 1: NANO-TASK
print("\n[SCENARIO 1] NANO-TASK AUTOMATION ($0.05)")
res1 = msft_agent.call_agent("verify_tax_id", 0.05, "Routine check")
print(f"RESULT: {res1}")

# SCENARIO 2: ZK-PRIVACY & COMPLIANCE
print("\n[SCENARIO 2] COMPLIANCE AUDIT")
mock_log = {"sender": msft_agent.did, "task": "generate_report", "amount": 500.0, "decision": "ALLOW"}
# FIX: Use the updated method name 'run_active_audit'
decision, audit_report = auditor.run_active_audit(mock_log)
print(f"VERDICT: {decision} | LAW: {audit_report['grounded_law']}")

# SCENARIO 3: HIGH RISK
print("\n[SCENARIO 3] HIGH-RISK ($5,000)")
print("📡 ACTION: Go to http://localhost:8000 (Admin Key: uaip-secret-123) and APPROVE.")
res3 = msft_agent.call_agent("wire_transfer", 5000.0, "Vendor payout")
print(f"FINAL RESULT: {res3}")
