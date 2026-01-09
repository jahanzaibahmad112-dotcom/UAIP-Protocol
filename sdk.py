import requests
import time
import nacl.signing
import nacl.encoding
import json
import hashlib
import uuid

class UAIP_Enterprise_SDK:
    """
    UAIP Enterprise SDK v1.0
    The 'Secure Passport' for Autonomous AI Agents.
    Handles Identity (Layer 2), JIT Polling (Layer 3), and Cryptographic Signing.
    """
    def __init__(self, agent_name: str, company_name: str, gateway_url: str = "http://localhost:8000"):
        self.agent_name = agent_name
        self.company = company_name.lower()
        self.gateway_url = gateway_url

        # 1. GENERATE CRYPTOGRAPHIC KEYS (Math-based Identity)
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        
        # Public Key (The 'Passport Number' we show the world)
        self.public_key_hex = self.verify_key.encode(nacl.encoding.HexEncoder).decode()

        # 2. GENERATE GLOBAL DID (Self-Sovereign ID)
        # Mirrors Bitcoin/Ethereum style address generation
        pub_hash = hashlib.sha256(self.public_key_hex.encode()).hexdigest()[:12]
        self.did = f"did:uaip:{self.company}:{pub_hash}"

        # 3. LAYER 1: AUTO-ONBOARDING
        # Automatically registers the agent in the Global Discovery Service
        try:
            requests.post(f"{self.gateway_url}/v1/register", json={
                "agent_id": self.did,
                "name": self.agent_name,
                "company": self.company,
                "public_key": self.public_key_hex
            })
            print(f"🚀 {self.agent_name} ONLINE | DID: {self.did}")
        except Exception as e:
            print(f"⚠️ Registration failed. Gateway might be offline: {e}")

    def _generate_signature(self, data_dict: dict) -> str:
        """
        Signs the data payload with the agent's private key.
        This provides the 'Proof of Identity' for the Gateway.
        """
        # Ensure consistent ordering so the math always matches
        msg = json.dumps(data_dict, sort_keys=True).encode('utf-8')
        signed = self.signing_key.sign(msg)
        return signed.signature.hex()

    def call_agent(self, task: str, amount: float, intent: str, chain: str = "BASE"):
        """
        The Master 'Secure Call'. Handles Interop, Security, and Settlement.
        """
        # Details of the transaction
        transaction_data = {
            "task_details": task,
            "nonce": uuid.uuid4().hex, # Prevents 'Replay Attacks'
            "timestamp": time.time()
        }

        # 1. CRYPTOGRAPHIC SIGNING (Fixes Missing Signature Bug)
        signature = self._generate_signature(transaction_data)

        # 2. THE UAIP PACKET
        packet = {
            "sender_id": self.did,
            "task": task,
            "amount": amount,
            "chain": chain,
            "intent": intent,
            "data": transaction_data,
            "signature": signature,      # The 'Stamp'
            "public_key": self.public_key_hex # The 'Mirror' for verification
        }

        # 3. EXECUTION
        try:
            res = requests.post(f"{self.gateway_url}/v1/execute", json=packet).json()
            
            if res.get('status') == "PAUSED":
                req_id = res['request_id']
                return self._poll_for_human_approval(req_id, task)
            
            return res
        except Exception as e:
            return {"status": "ERROR", "message": f"Connection to Gateway failed: {e}"}

    def _poll_for_human_approval(self, req_id: str, task: str):
        """
        Layer 3: Human-in-the-Loop Polling.
        Listens for the 'Big Red Button' on the dashboard.
        """
        print(f"⌛ [SECURITY] Action '{task}' requires human approval. Pausing agent...")
        
        while True:
            try:
                # Check the status from the Gateway
                response = requests.get(f"{self.gateway_url}/v1/check/{req_id}").json()
                status = response.get("status")

                if status == "APPROVED":
                    print("✅ HUMAN APPROVED. Transaction finalized.")
                    return {"status": "SUCCESS", "message": "Manual approval received."}
                
                # FIX: Breaks the 'Loop of Death'
                if status == "DENIED" or status == "REJECTED":
                    print("🚫 HUMAN DENIED. Action terminated.")
                    return {"status": "BLOCKED", "message": "The human commander rejected this action."}
                
                # Wait 2 seconds before checking again (prevents server spam)
                time.sleep(2)
            except Exception as e:
                print(f"⚠️ Polling error: {e}")
                time.sleep(5)
