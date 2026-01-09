from sdk import UAIP_Enterprise_SDK
from compliance import ComplianceAuditor

# 1. Start Two Agents from Different Companies
microsoft_agent = UAIP_Enterprise_SDK("Azure_Bot", "Microsoft")
openai_agent = UAIP_Enterprise_SDK("GPT_Worker", "OpenAI")

auditor = ComplianceAuditor()

print("\n--- 🦾 UAIP SECURE ECONOMY DEMO ---")

# SCENARIO 1: Automated Low-Risk Task
print("\n[SCENARIO 1] Microsoft Agent hires OpenAI Agent for Weather Data ($0.05)")
result = microsoft_agent.call_agent("get_weather", 0.05, "Routine weather check")
print(result)

# SCENARIO 2: High-Risk Task (Triggers AgentGuard & HITL)
print("\n[SCENARIO 2] Microsoft Agent attempts Large Transfer ($5,000)")
print("PLEASE GO TO THE DASHBOARD AND CLICK APPROVE!")
result = microsoft_agent.call_agent("withdraw_funds", 5000.0, "Emergency liquidity move")
print(result)

# SCENARIO 3: Compliance Audit (RAG + Llama-3-Legal)
print("\n[SCENARIO 3] Running Forensic Compliance Audit...")
mock_log = {"task": "withdraw_funds", "decision": "ALLOW", "risk": "High"}
report = auditor.run_audit(mock_log)
print(f"Audit Report: {report['audit_id']} | Law Cited: {report['grounded_law']} | Status: {report['status']}")

print("\n--- DEMO COMPLETE ---")
