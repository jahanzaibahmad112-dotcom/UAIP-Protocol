from sdk import UAIP_Enterprise_SDK
from compliance import ComplianceAuditor
import time
import json

# --- 1. SETUP: IDENTITY & INTEROPERABILITY ---
# We simulate a real-world partnership: A Microsoft Agent hiring an OpenAI Agent.
# Every time you run this, new cryptographic DIDs (passports) are generated.

SECRET_CODE = 987654321  # The ZK-Secret known only to the Microsoft Agent
auditor = ComplianceAuditor()

print("\n" + "="*60)
print("🛡️  UAIP + AGENTGUARD: THE SECURE AGENTIC ECONOMY DEMO")
print("="*60)

# Initialize the Microsoft Procurement Agent
# EXPECT: Cryptographic Identity Generation (DID)
print("\n[STEP 1] INITIALIZING ENTERPRISE IDENTITIES...")
msft_agent = UAIP_Enterprise_SDK("Azure_Procurement_Bot", "Microsoft", SECRET_CODE)
openai_agent_did = "did:uaip:openai:target_worker_0xabc" # The destination

time.sleep(1)

# --- SCENARIO 1: NANO-PAYMENTS & AUTOMATION ---
# Show how the system handles tiny tasks that banks can't handle.
print("\n" + "-"*60)
print("[SCENARIO 1] NANO-TASK AUTOMATION ($0.05)")
print("Logic: Low risk. System should AUTO-APPROVE and apply the $0.01 PROFIT FLOOR.")

res1 = msft_agent.call_agent("verify_tax_id", 0.05, "Routine vendor validation")

print(f"\nRESULT: {res1}")
print("PROFIT LOG: Protocol collected $0.01 flat fee (High Margin Tier A).")


# --- SCENARIO 2: ZK-PRIVACY & COMPLIANCE ---
# Show how we verify identity without seeing secrets.
print("\n" + "-"*60)
print("[SCENARIO 2] ZERO-KNOWLEDGE (ZK) PRIVACY & AUDIT")
print("Logic: Proving authority for a $500 task WITHOUT sending the secret code.")

res2 = msft_agent.call_agent("generate_market_report", 500.0, "Quarterly analysis")

# Simulate the Compliance Engine citing the law
print("\n[LEGAL AUDIT ACTIVE] Analyzing decision against SOC2 & EU AI Act...")
mock_log = {"sender": msft_agent.did, "task": "generate_market_report", "amount": 500.0, "decision": "ALLOW"}
audit_report = auditor.verify_and_audit(mock_log)

print(f"VERDICT: {audit_report['verdict']}")
print(f"LAW CITED: {audit_report['law']}")


# --- SCENARIO 3: HIGH-RISK GOVERNANCE (HITL) ---
# Show the "Big Red Button" where the human takes control.
print("\n" + "-"*60)
print("[SCENARIO 3] HIGH-RISK FINANCIAL CLEARING ($5,000)")
print("Logic: High Value detected. Protocol will PAUSE for Human Authorization.")
print("\n📡 ACTION: Go to http://localhost:8000 and enter Admin Key: uaip-secret-123")
print("📡 ACTION: Click 'Approve' to resume the agent.")

# This call will hang and wait for YOU to click approve in the browser
res3 = msft_agent.call_agent("wire_transfer_payout", 5000.0, "Vendor contract fulfillment")

print(f"\nFINAL RESULT: {res3}")
print("PROFIT LOG: Protocol collected 1% ($50.00) Fee for managed governance.")


# --- SCENARIO 4: SECURITY & KILL-SWITCH ---
# Show how we terminate a rogue agent instantly.
print("\n" + "-"*60)
print("[SCENARIO 4] THE KILL-SWITCH (SAFETY)")
print("Logic: If an agent is compromised, we revoke its DID globally.")

print(f"\n📡 ACTION: On the Dashboard, click 'TERMINATE' on the agent {msft_agent.did}")
input("Press Enter once you have terminated the agent in the dashboard...")

print("\nAttempting one last transaction with the terminated agent...")
res4 = msft_agent.call_agent("final_ping", 0.01, "Checking status")
print(f"RESULT: {res4}")
print("SAFETY CONFIRMED: Terminal agent was blocked by the Zero-Trust layer.")

print("\n" + "="*60)
print("✅ END-TO-END DEMO COMPLETE: INTEROPERABILITY & SAFETY SECURED")
print("="*60 + "\n")
