from sdk import UAIP_Secure_SDK

# Now you just give the agent a human name
# The SDK creates the 'did:uaip:...' automatically!
client = UAIP_Secure_SDK(agent_name="Founder_Agent_01")

print("\n--- 🦾 TESTING SECURE IDENTITY ---")

# Task 1: A routine query
print("\n[Step 1] Requesting Weather Data...")
print(client.call("get_weather", 0.05))

# Task 2: A risky bank transfer
print("\n[Step 2] Requesting Large Transfer...")
print(client.call("withdraw_funds", 5000.0))
