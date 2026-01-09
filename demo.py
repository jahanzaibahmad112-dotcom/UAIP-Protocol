import time
from sdk import UAIP_Enterprise_SDK
from compliance import ComplianceAuditor

# 1. INITIALIZE THE ACTORS
# We create two agents from different 'Walled Gardens' (Microsoft and OpenAI)
# The SDK automatically generates their DNA (DIDs) and Passports (Keys)
microsoft_agent = UAIP_Enterprise_SDK(agent_name="Azure_Procurement_Bot", company_name="Microsoft")
openai_agent = UAIP_Enterprise_SDK(agent_name="GPT_Data_Vendor", company_name="OpenAI")

# Initialize the Legal Auditor for the final report
auditor = ComplianceAuditor()

print("\n" + "="*50)
print("🛡️  UAIP + AGENTGUARD: SECURE ECONOMY DEMO")
print("="*50)

# --- SCENARIO 1: THE NANO-PAYMENT (AUTO-APPROVED) ---
print(f"\n[SCENARIO 1] CROSS-COMPANY NANO-TRANSACTION")
print(f"Goal: Microsoft Agent hires OpenAI Agent for a micro-task.")

# Note: This handles Identity, Signing, and 0.5% Tax automatically
result_1 = microsoft_agent.call_agent(
    task="verify_code_snippet", 
    amount=0.05, 
    intent="Routine code verification for dev team",
    chain="BASE"
)
print(f"Result: {result_1}")


# --- SCENARIO 2: THE HIGH-RISK MOVE (GOVERNANCE ACTIVE) ---
print(f"\n[SCENARIO 2] HIGH-VALUE TRANSACTION & GOVERNANCE")
print(f"Goal: Microsoft Agent attempts to move $5,000.")
print(f"EXPECTED: System will detect HIGH RISK and PAUSE for human approval.")

# This triggers the 'JIT' (Just-In-Time) Authorization logic
print("\n📡 REQUEST SENT. CHECK YOUR BROWSER DASHBOARD (http://localhost:8000) TO 'APPROVE'!")

result_2 = microsoft_agent.call_agent(
    task="emergency_liquidity_transfer", 
    amount=5000.00, 
    intent="Moving funds to secondary reserve",
    chain="SOLANA"
)
print(f"Result: {result_2}")


# --- SCENARIO 3: THE LEGAL AUDIT (FORENSIC PROOF) ---
print(f"\n[SCENARIO 3] RAG-POWERED COMPLIANCE AUDIT")
print(f"Goal: Generate a forensic report using Llama-3-Legal logic.")

# We simulate the log entry that would be in the database
mock_log = {
    "sender": microsoft_agent.did,
    "task": "emergency_liquidity_transfer",
    "amount": 5000.00,
    "decision": "ALLOW", # Since you just clicked approve
    "risk": "High"
}

audit_report = auditor.run_audit(mock_log)

print("\n--- 📄 FORENSIC AUDIT REPORT ---")
print(f"Audit ID:     {audit_report['audit_id']}")
print(f"Status:       {audit_report['audit_status']}")
print(f"Law Cited:    {audit_report['grounded_law']}")
print(f"AI Reasoning: {audit_report['verification_reasoning']}")
print(f"Legal Model:  {audit_report['model_metadata']}")
print(f"Disclaimer:   {audit_report['disclaimer']}")

print("\n" + "="*50)
print("✅ DEMO COMPLETE: INTEROPERABILITY, SECURITY, & COMPLIANCE VERIFIED")
print("="*50)
