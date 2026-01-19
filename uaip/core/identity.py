"""Cryptographic identity management using DIDs."""

import hashlib
import base58
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder


class DIDGenerator:
    """Generate and verify Decentralized Identifiers (DIDs)."""
    
    def __init__(self):
        # Generate Ed25519 keypair
        signing_key = SigningKey.generate()
        self._private_key = signing_key
        self._public_key = signing_key.verify_key
        
        self.private_key = signing_key.encode(
            encoder=Base64Encoder
        ).decode('utf-8')
        
        self.public_key = self._public_key.encode(
            encoder=Base64Encoder
        ).decode('utf-8')
    
    def generate_did(self, name: str, company: str) -> str:
        """
        Generate a DID from public key.
        
        Format: did:uaip:{base58(public_key_hash)}
        """
        # Hash the public key
        pub_key_bytes = self._public_key.encode()
        key_hash = hashlib.sha256(pub_key_bytes).digest()
        
        # Encode as base58
        encoded = base58.b58encode(key_hash).decode('utf-8')
        
        return f"did:uaip:{encoded}"
    
    def sign_message(self, message: str) -> str:
        """Sign a message with private key."""
        message_bytes = message.encode('utf-8')
        signed = self._private_key.sign(message_bytes)
        return signed.signature.hex()
    
    def verify_identity(self, did: str) -> bool:
        """Verify this DID matches our public key."""
        # Extract base58 part
        expected_hash = did.split('did:uaip:')[1]
        
        # Recompute hash from our public key
        pub_key_bytes = self._public_key.encode()
        key_hash = hashlib.sha256(pub_key_bytes).digest()
        actual_hash = base58.b58encode(key_hash).decode('utf-8')
        
        return expected_hash == actual_hash
    
    @staticmethod
    def verify_external_signature(
        message: str,
        signature: str,
        public_key_b64: str
    ) -> bool:
        """Verify a signature from another agent."""
        try:
            # Decode public key
            verify_key = VerifyKey(
                public_key_b64,
                encoder=Base64Encoder
            )
            
            # Verify signature
            message_bytes = message.encode('utf-8')
            signature_bytes = bytes.fromhex(signature)
            
            verify_key.verify(message_bytes, signature_bytes)
            return True
        except Exception:
            return False