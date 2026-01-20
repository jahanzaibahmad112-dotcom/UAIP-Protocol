"""Tests for Compliance Auditor"""
import pytest
from decimal import Decimal
from uaip.compliance import ComplianceAuditor

class TestComplianceAuditor:
    def test_initialization(self):
        """Test compliance auditor initializes"""
        auditor = ComplianceAuditor()
        assert auditor is not None
    
    def test_blocked_keywords(self):
        """Test that prohibited keywords are blocked"""
        auditor = ComplianceAuditor()
        
        log = {
            "sender": "did:uaip:test",
            "task": "offshore account setup",
            "amount": "100.0",
            "timestamp": 1234567890
        }
        
        status, report = auditor.run_active_audit(log)
        assert status == "TERMINATE"
    
    def test_normal_transaction(self):
        """Test normal transaction passes"""
        auditor = ComplianceAuditor()
        
        log = {
            "sender": "did:uaip:test",
            "task": "process invoice",
            "amount": "50.0",
            "timestamp": 1234567890
        }
        
        status, report = auditor.run_active_audit(log)
        assert status == "PASSED"
    
    def test_high_value_requires_approval(self):
        """Test high value transactions require approval"""
        auditor = ComplianceAuditor()
        
        log = {
            "sender": "did:uaip:test",
            "task": "large payment",
            "amount": "5000.0",
            "timestamp": 1234567890
        }
        
        status, report = auditor.run_active_audit(log)
        assert status == "PENDING_ENFORCED"