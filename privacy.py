import hashlib
import hmac

class ZK_Privacy:
    """
    ZK-Lite: Proves an agent has 'Authorized Data' without 
    showing the data to the Gateway.
    """
    @staticmethod
    def generate_proof(secret_data: str, salt: str):
        # Creates a 'Commitment' (You can't see the secret, but you can verify it)
        return hmac.new(salt.encode(), secret_data.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_proof(proof: str, secret_data: str, salt: str):
        # Verification happens without the secret ever being stored on the Gateway
        expected = hmac.new(salt.encode(), secret_data.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(proof, expected)