import requests, time

class UAIP_Secure_SDK:
    def __init__(self, agent_id, gateway_url="http://localhost:8000"):
        self.agent_id = agent_id
        self.gateway_url = gateway_url

    def call(self, task, amount, chain="BASE"):
        # The keys here MUST match the Gateway's UAIPRequest model exactly
        payload = {
            "sender_id": self.agent_id,
            "task": task,
            "amount": amount,
            "chain": chain,
            "data": {}
        }
        
        try:
            res = requests.post(f"{self.gateway_url}/v1/execute", json=payload).json()
            
            if res.get('status') == "PAUSED":
                req_id = res['request_id']
                print(f"⌛ [PAUSED] Human approval needed for: {task}")
                while True:
                    status = requests.get(f"{self.gateway_url}/v1/check/{req_id}").json()['status']
                    if status == "APPROVED": return "✅ APPROVED"
                    if status == "DENIED": return "❌ DENIED"
                    time.sleep(2)
            return "✅ SUCCESS"
        except Exception as e:
            return f"❌ ERROR: {e}"
