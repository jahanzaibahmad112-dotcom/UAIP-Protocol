import requests, time, uuid, json, hashlib, nacl.signing, nacl.encoding
from privacy import ZK_Privacy

class UAIP_Enterprise_SDK:
    def __init__(self, agent_name, company_name, secret_code: int):
        self.gateway = "http://localhost:8000"
        self.secret_code = secret_code
        self.sk = nacl.signing.SigningKey.generate()
        self.pk = self.sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
        self.did = f"did:uaip:{company_name.lower()}:{hashlib.sha256(self.pk.encode()).hexdigest()[:10]}"
        self.zk_commitment = ZK_Privacy.generate_commitment(self.secret_code)

        # 1. Deterministic Signed Registration
        reg_data = {"agent_id": self.did, "zk_commitment": self.zk_commitment, "public_key": self.pk, "timestamp": time.time()}
        msg = json.dumps(reg_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        sig = self.sk.sign(msg).signature.hex()
        requests.post(f"{self.gateway}/v1/register", json={"registration_data": reg_data, "signature": sig, "public_key": self.pk})
        print(f"✅ ONBOARDED: {self.did}")

    def call_agent(self, task, amount, intent):
        proof = ZK_Privacy.create_proof(self.secret_code, self.zk_commitment)
        data = {"task": task, "amount": float(amount), "intent": intent, "nonce": uuid.uuid4().hex, "timestamp": time.time()}
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        sig = self.sk.sign(msg).signature.hex()

        packet = {"sender_id": self.did, "task": task, "amount": amount, "chain": "BASE", "intent": intent, "data": data, "signature": sig, "public_key": self.pk, "nonce": data["nonce"], "timestamp": data["timestamp"], "zk_proof": proof}
        
        res = requests.post(f"{self.gateway}/v1/execute", json=packet).json()
        if res.get("status") == "PAUSED":
            req_id = res["request_id"]
            while True:
                status = requests.get(f"{self.gateway}/v1/check/{req_id}").json()["status"]
                if status == "APPROVED": return "✅ APPROVED"
                if status == "DENIED": return "❌ REJECTED"
                time.sleep(2)
        return res
