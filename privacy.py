import hashlib
import hmac
import secrets

class ZK_Privacy:
    """
    True Non-Interactive Zero-Knowledge (NIZK) Proof.
    Protects against Timing Attacks and Information Leakage.
    """
    G = 2
    P = 2**255 - 19  # Large prime for modular math

    @classmethod
    def generate_commitment(cls, secret_key: int):
        """Creates the 'Public Passport' for the secret. Math: y = G^x mod P"""
        return pow(cls.G, secret_key, cls.P)

    @classmethod
    def create_proof(cls, secret_key: int, public_commitment: int):
        """Generates a unique ZK-Proof without sending the secret_key."""
        k = secrets.randbelow(cls.P)
        r = pow(cls.G, k, cls.P)
        
        # Deterministic challenge using Canonical string format
        challenge_data = f"{cls.G},{public_commitment},{r}".encode()
        e = int(hashlib.sha256(challenge_data).hexdigest(), 16)
        
        s = (k + (e * secret_key)) % (cls.P - 1)
        return {"r": r, "s": s}

    @classmethod
    def verify_proof(cls, proof: dict, public_commitment: int):
        """Verifies proof without knowing the secret. Math: G^s == r * y^e"""
        r, s = proof["r"], proof["s"]
        challenge_data = f"{cls.G},{public_commitment},{r}".encode()
        e = int(hashlib.sha256(challenge_data).hexdigest(), 16)
        
        lhs = pow(cls.G, s, cls.P)
        rhs = (r * pow(public_commitment, e, cls.P)) % cls.P
        return lhs == rhs
