import requests
import time
import nacl.signing
import nacl.encoding
import json
import hashlib

class UAIP_Secure_SDK:
    def __init__(self, agent_name, gateway_url="http://localhost:8000"):
        """
        Initializes the agent with a secure, cryptographic DID Passport.
        """
        self.agent_name = agent_name
        self.gateway_url = gateway_url
        
        # 1. GENERATE KEYS (The Secret and the Passport)
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        
        self.private_key_hex = self.signing_key.encode(nacl.encoding.HexEncoder).decode()
        self.public_key_hex = self.verify_key.encode(nacl.encoding.HexEncoder).decode()

        # 2. GENERATE THE DID (The Digital License Plate)
        # We hash the public key to create a unique, immutable ID string
        public_hash = hashlib.sha256(self.public_key_hex.encode()).hexdigest()[:24]
        self.did = f"did:uaip:{public_hash}"
        
        print(f"🆔 IDENTITY GENERATED")
        print(f"Agent Name: {self.agent_name}")
        print(f"Agent DID:  {self.did}")

    def sign_request(self, payload):
        """Signs data so the Gateway knows it came from THIS DID."""
        payload['timestamp'] = time.time()
        payload['sender_did'] = self.did # Attach our DID to every message
        
        msg_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = self.signing_key.sign(msg_bytes).signature.hex()
        return signature

    def call(self, task, amount, data_payload={}):
        """Sends a secure, signed request to the Gateway."""
        signature = self.sign_request(data_payload)
        
        # The official UAIP Packet
        packet = {
            "sender_id": self.did, # We use the DID as the main ID
            "task": task,
            "amount": amount,
            "chain": "BASE",
            "data": data_payload,
            "public_key": self.public_key_hex,
            "signature": signature
        }
        
        try:
            res = requests.post(f"{self.gateway_url}/v1/execute", json=packet).json()
            
            if res.get('status') == "PAUSED":
                req_id = res['request_id']
                print(f"⌛ [AGENT GUARD] Action '{task}' paused for DID {self.did}.")
                print(f"Waiting for Human Commander...")
                return self.poll_for_approval(req_id)
            
            return res
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def poll_for_approval(self, req_id):
        """Checks the gateway until a human clicks Approve or Deny."""
        while True:
            status = requests.get(f"{self.gateway_url}/v1/check-status/{req_id}").json()['status']
            if status == "APPROVED":
                print("✅ HUMAN APPROVED.")
                return {"status": "SUCCESS"}
            if status == "DENIED":
                print("🚫 HUMAN DENIED.")
                return {"status": "BLOCKED"}
            time.sleep(2)
