import requests, time, uuid

class UAIP_Enterprise_SDK:
    def __init__(self, agent_name, owner_email):
        """Layer 5: Easy Onboarding & Layer 2: Identity Binding"""
        self.agent_id = f"did:uaip:{uuid.uuid4().hex[:12]}"
        self.agent_name = agent_name
        self.owner = owner_email
        self.gateway = "http://localhost:8000"

        # Auto-Register (Layer 1 Discovery)
        requests.post(f"{self.gateway}/v1/register", json={
            "agent_id": self.agent_id,
            "name": self.agent_name,
            "owner": self.owner,
            "capabilities": ["general_task"]
        })
        print(f"🚀 Agent {agent_name} Onboarded & Registered.")

    def request_action(self, task, amount, context):
        """Layer 3: JIT Request with Intent"""
        payload = {
            "sender_id": self.agent_id,
            "task": task,
            "amount": amount,
            "context": context,
            "data": {}
        }
        
        res = requests.post(f"{self.gateway}/v1/execute", params=payload).json()
        
        if res.get('status') == "PAUSED":
            print(f"⌛ [JIT PROTECTION] Action paused for security review...")
            req_id = res['request_id']
            while True:
                status = requests.get(f"{self.gateway}/v1/check/{req_id}").json()['status']
                if status == "APPROVED": return "✅ APPROVED"
                time.sleep(2)
        
        return "✅ SUCCESS"
