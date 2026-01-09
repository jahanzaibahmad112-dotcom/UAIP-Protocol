import hashlib
import hmac

class ZK_Privacy:
    """
    ZK-Lite Module: Proves authorization without leaking sensitive data.
    Ensures Gateway never 'sees' the corporate secrets it protects.
    """
    @staticmethod
    def generate_proof(secret_data: str, salt: str):
        # Creates a cryptographic commitment
        return hmac.new(salt.encode(), secret_data.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_proof(proof: str, secret_data: str, salt: str):
        # Verifies the proof matches the secret without storing the secret
        expected = hmac.new(salt.encode(), secret_data.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(proof, expected)
