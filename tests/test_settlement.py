"""Tests for Financial Settlement Engine"""
import pytest
from decimal import Decimal
from uaip.settlement import UAIPFinancialEngine

class TestSettlementEngine:
    def test_initialization(self):
        """Test engine initializes"""
        engine = UAIPFinancialEngine()
        assert engine is not None
    
    def test_tier_a_fee(self):
        """Test Tier A fee calculation (≤$10)"""
        engine = UAIPFinancialEngine()
        fee = engine.calculate_fee(Decimal("5.00"))
        assert fee == Decimal("0.01")
    
    def test_tier_b_fee(self):
        """Test Tier B fee calculation ($10-$10k)"""
        engine = UAIPFinancialEngine()
        fee = engine.calculate_fee(Decimal("100.00"))
        assert fee == Decimal("1.00")  # 1% of 100
    
    def test_tier_c_fee(self):
        """Test Tier C fee calculation (>$10k)"""
        engine = UAIPFinancialEngine()
        fee = engine.calculate_fee(Decimal("20000.00"))
        # $10 + 0.5% of 20000 = $10 + $100 = $110
        assert fee == Decimal("110.00")
    
    def test_process_settlement(self):
        """Test settlement processing"""
        engine = UAIPFinancialEngine()
        
        result = engine.process_settlement(
            payer_did="did:uaip:payer",
            amount_usd=100.00,
            payee_did="did:uaip:payee",
            chain="BASE"
        )
        
        assert result['status'] == 'SUCCESS'
        assert 'tx_id' in result