from sdk import UAIP_Secure_SDK

client = UAIP_Secure_SDK(agent_id="Founder_Bot")

print("\n--- RUNNING DEMO ---")

print("Task 1: Small request...")
print(client.call("Get Weather", 0.05))

print("\nTask 2: Large Bank Transfer...")
print(client.call("Transfer Funds", 5000.0))
