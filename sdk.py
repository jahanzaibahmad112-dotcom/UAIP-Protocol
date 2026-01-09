import requests, time, uuid, nacl.signing, nacl.encoding, json, hashlib

class UAIP_Enterprise_SDK:
    def __init__(self, agent_name, company_name):
        self.company = company_name.lower()
        self.gateway = "http://localhost:8000"
        
        # 1. Identity Creation (Math-based DID)
        self.sk = nacl.signing.SigningKey.generate()
        self.pk = self.sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
        pub_hash = hashlib.sha256(self.pk.encode()).hexdigest()[:10]
        self.did = f"did:uaip:{self.company}:{pub_hash}"

        # 2. Layer 1 Discovery: Auto-Onboard
        requests.post(f"{self.gateway}/v1/register", json={
            "agent_id": self.did, "name": agent_name, "company": self.company
        })
        print(f"🚀 {agent_name} Onboarded. DID: {self.did}")

    def call_agent(self, task, amount, intent, chain="BASE"):
        """Automated Hiring Flow: Discover -> Contract -> Secure Execute"""
        payload = {
            "sender_id": self.did,
            "task": task,
            "amount": amount,
            "chain": chain,
            "intent": intent,
            "data": {}
        }
        
        res = requests.post(f"{self.gateway}/v1/execute", json=payload).json()
        
        if res.get('status') == "PAUSED":
            req_id = res['request_id']
            print(f"⌛ [JIT PROTECTION] Action paused for human commander...")
            while True:
                status = requests.get(f"{self.gateway}/v1/check/{req_id}").json()['status']
                if status == "APPROVED": return "✅ SUCCESS (Human Approved)"
                time.sleep(2)
        return "✅ SUCCESS"
