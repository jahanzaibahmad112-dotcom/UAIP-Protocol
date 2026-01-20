"""Tests for ZK Privacy System"""
import pytest
from uaip.privacy import ZK_Privacy

class TestZKPrivacy:
    def test_generate_secret(self):
        """Test secret key generation"""
        secret = ZK_Privacy.generate_secret_key()
        assert secret > 0
    
    def test_generate_commitment(self):
        """Test commitment generation"""
        secret = 12345
        commitment = ZK_Privacy.generate_commitment(secret)
        assert commitment > 0
    
    def test_create_and_verify_proof(self):
        """Test proof creation and verification"""
        secret = ZK_Privacy.generate_secret_key()
        commitment = ZK_Privacy.generate_commitment(secret)
        
        proof = ZK_Privacy.create_proof(secret, commitment)
        
        assert 'r' in proof
        assert 's' in proof
        
        is_valid = ZK_Privacy.verify_proof(proof, commitment)
        assert is_valid == True
    
    def test_invalid_proof_fails(self):
        """Test that invalid proofs are rejected"""
        secret = ZK_Privacy.generate_secret_key()
        commitment = ZK_Privacy.generate_commitment(secret)
        
        # Create proof with correct secret
        proof = ZK_Privacy.create_proof(secret, commitment)
        
        # Try to verify with wrong commitment
        wrong_commitment = ZK_Privacy.generate_commitment(secret + 1)
        
        is_valid = ZK_Privacy.verify_proof(proof, wrong_commitment)
        assert is_valid == False
```