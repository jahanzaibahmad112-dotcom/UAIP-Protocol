from sdk import UAIP_Secure_SDK
import nacl.signing
import nacl.encoding

# 1. Setup Identity
priv_key = nacl.signing.SigningKey.generate().encode(nacl.encoding.HexEncoder).decode()
client = UAIP_Secure_SDK(agent_id="Alpha_Agent_01", private_key_hex=priv_key)

print("--- 🦾 UAIP + AgentGuard System Start ---")

# TEST 1: Routine Task (Auto-approved)
print("\nTask 1: Getting Market Data ($0.05)")
print(client.call("get_market_data", 0.05, {"symbol": "BTC"}))

# TEST 2: High Risk Task (Will trigger the Dashboard!)
print("\nTask 2: Sending Large Bank Wire ($5,000)")
print("Check your browser dashboard to Approve this!")
result = client.call("bank_wire_transfer", 5000.0, {"to": "Account_XYZ"})
print(f"Result: {result}")