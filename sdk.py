import requests
import time
import nacl.signing
import nacl.encoding
import json

class UAIP_Secure_SDK:
    def __init__(self, agent_id, private_key_hex, gateway_url="http://localhost:8000"):
        self.agent_id = agent_id
        self.gateway_url = gateway_url
        self.signing_key = nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)
        self.public_key = self.signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode()

    def sign_request(self, data):
        data['timestamp'] = time.time()
        msg = json.dumps(data, sort_keys=True).encode('utf-8')
        return self.signing_key.sign(msg).signature.hex()

    def call(self, task, amount, payload):
        signature = self.sign_request(payload)
        
        res = requests.post(f"{self.gateway_url}/v1/execute", json={
            "sender_id": self.agent_id,
            "task": task,
            "amount": amount,
            "data": payload,
            "public_key": self.public_key,
            "signature": signature
        }).json()

        if res.get('status') == "PAUSED":
            req_id = res['request_id']
            print(f"⌛ [AGENT GUARD] Action '{task}' paused. Waiting for human commander...")
            while True:
                status = requests.get(f"{self.gateway_url}/v1/check/{req_id}").json()['status']
                if status == "APPROVED":
                    print("✅ APPROVED. Proceeding...")
                    return {"status": "SUCCESS", "data": "Action Completed"}
                if status == "DENIED":
                    return {"status": "BLOCKED", "reason": "Human denied the request."}
                time.sleep(2)
        
        return res