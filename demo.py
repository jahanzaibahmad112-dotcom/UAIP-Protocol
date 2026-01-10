from sdk import UAIP_Enterprise_SDK
import time

# Secret code for ZK-Identity
SECRET = 987654321

# Initialize Agents
client = UAIP_Enterprise_SDK("Finance_Bot", "OpenAI", SECRET)

print("\n[Scenario 1] Nano-task ($0.05) - EXPECT: Auto-approve & $0.01 fee")
print(client.call_agent("verify_email", 0.05, "Routine check"))

print("\n[Scenario 2] High-risk ($5,000) - EXPECT: Pause & HITL Dashboard")
print("Go to http://localhost:8000 (Admin Key: uaip-admin-secret-999) to approve.")
print(client.call_agent("wire_transfer", 5000.0, "Corporate payout"))
