import requests
import uuid

class UAIP_SDK:
    """The tool developers use to join the UAIP Network."""
    
    def __init__(self, gateway_url):
        self.gateway_url = gateway_url

    def join_network(self, agent_name, task_name, price):
        # Simplifies registration for the developer
        agent_id = str(uuid.uuid4())
        manifest = {
            "agent_id": agent_id,
            "name": agent_name,
            "capabilities": [{"task": task_name}],
            "economics": {"price": price}
        }
        # In a real SDK, we would handle key generation here
        payload = {"agent_id": agent_id, "public_key": "sample_key", "manifest": manifest}
        requests.post(f"{self.gateway_url}/register", json=payload)
        return agent_id

    def find_and_call(self, task):
        # Automatically finds an agent for the user
        response = requests.get(f"{self.gateway_url}/discover/{task}")
        agents = response.json()
        if not agents:
            return "No agents found."
        return f"Found {len(agents)} agents. Best match: {agents[0]['agent_id']}"