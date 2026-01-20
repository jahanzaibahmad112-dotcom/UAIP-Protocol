Install test dependencies:
pip install pytest pytest-cov pytest-mock requests-mock
Run tests:
pytest tests/ -v --cov=uaip --cov-report=term-missing
"""
import pytest
import json
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock
from uaip.sdk import UAIP_Enterprise_SDK
class TestSDKInitialization:
"""Test SDK initialization and validation"""
def test_valid_initialization(self):
    """Test successful SDK initialization"""
    sdk = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        gateway_url="http://localhost:8000",
        auto_register=False
    )
    
    assert sdk.agent_name == "TestBot"
    assert sdk.company_name == "TestCorp"
    assert sdk.did.startswith("did:uaip:")
    assert sdk.pk is not None

def test_invalid_agent_name(self):
    """Test that invalid agent names are rejected"""
    with pytest.raises(ValueError, match="Agent name"):
        UAIP_Enterprise_SDK(
            agent_name="",  # Empty name
            company_name="TestCorp",
            secret_code=12345,
            auto_register=False
        )

def test_invalid_company_name(self):
    """Test that invalid company names are rejected"""
    with pytest.raises(ValueError, match="Company name"):
        UAIP_Enterprise_SDK(
            agent_name="TestBot",
            company_name="Test@Corp!",  # Invalid characters
            secret_code=12345,
            auto_register=False
        )

def test_invalid_secret_code(self):
    """Test that invalid secret codes are rejected"""
    with pytest.raises(ValueError, match="Secret code"):
        UAIP_Enterprise_SDK(
            agent_name="TestBot",
            company_name="TestCorp",
            secret_code="not_a_number",  # Not an integer
            auto_register=False
        )

def test_invalid_gateway_url(self):
    """Test that invalid URLs are rejected"""
    with pytest.raises(ValueError, match="Gateway URL"):
        UAIP_Enterprise_SDK(
            agent_name="TestBot",
            company_name="TestCorp",
            secret_code=12345,
            gateway_url="not-a-valid-url",  # Missing protocol
            auto_register=False
        )
class TestSDKRegistration:
"""Test agent registration"""
@patch('uaip.sdk.requests.Session.post')
def test_successful_registration(self, mock_post):
    """Test successful agent registration"""
    mock_post.return_value = Mock(
        status_code=200,
        json=lambda: {"status": "REGISTERED", "agent_id": "did:uaip:test"}
    )
    
    sdk = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )
    
    result = sdk.register()
    
    assert result["status"] == "REGISTERED"
    assert sdk.stats['registrations'] == 1
    mock_post.assert_called_once()

@patch('uaip.sdk.requests.Session.post')
def test_registration_failure(self, mock_post):
    """Test handling of registration failures"""
    mock_post.return_value = Mock(
        status_code=500,
        json=lambda: {"detail": "Server error"}
    )
    
    sdk = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )
    
    with pytest.raises(RuntimeError, match="Registration failed"):
        sdk.register()
class TestSDKTransactions:
"""Test transaction processing"""
@pytest.fixture
def sdk(self):
    """Create SDK instance for testing"""
    return UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        gateway_url="http://localhost:8000",
        auto_register=False
    )

@patch('uaip.sdk.requests.Session.post')
def test_successful_transaction(self, mock_post, sdk):
    """Test successful transaction processing"""
    mock_post.return_value = Mock(
        status_code=200,
        json=lambda: {
            "status": "SUCCESS",
            "request_id": "req_123",
            "settlement": {
                "amount": 50.0,
                "fee": 0.5,
                "payout": 49.5,
                "tx_id": "tx_abc",
                "chain": "BASE"
            }
        }
    )
    
    result = sdk.call_agent(
        task="Test payment",
        amount=50.0,
        intent="Testing",
        chain="BASE",
        wait_for_approval=False
    )
    
    assert result["status"] == "SUCCESS"
    assert sdk.stats['successful_requests'] == 1
    assert sdk.stats['total_amount_processed'] > 0

def test_invalid_task(self, sdk):
    """Test that invalid tasks are rejected"""
    with pytest.raises(ValueError, match="Task"):
        sdk.call_agent(
            task="",  # Empty task
            amount=50.0,
            intent="Testing",
            chain="BASE"
        )

def test_invalid_amount(self, sdk):
    """Test that invalid amounts are rejected"""
    with pytest.raises(ValueError, match="Amount"):
        sdk.call_agent(
            task="Test",
            amount=-50.0,  # Negative amount
            intent="Testing",
            chain="BASE"
        )

def test_invalid_chain(self, sdk):
    """Test that invalid chains are rejected"""
    with pytest.raises(ValueError, match="chain"):
        sdk.call_agent(
            task="Test",
            amount=50.0,
            intent="Testing",
            chain="INVALID_CHAIN"
        )

@patch('uaip.sdk.requests.Session.post')
def test_pending_approval(self, mock_post, sdk):
    """Test high-value transaction requiring approval"""
    mock_post.return_value = Mock(
        status_code=200,
        json=lambda: {
            "status": "PENDING_APPROVAL",
            "request_id": "req_456",
            "message": "Requires approval"
        }
    )
    
    result = sdk.call_agent(
        task="High value payment",
        amount=5000.0,
        intent="Testing",
        chain="BASE",
        wait_for_approval=False
    )
    
    assert result["status"] == "PENDING_APPROVAL"
    assert "request_id" in result
class TestSDKUtilities:
"""Test SDK utility methods"""
@pytest.fixture
def sdk(self):
    return UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )

def test_get_statistics(self, sdk):
    """Test statistics retrieval"""
    stats = sdk.get_statistics()
    
    assert 'agent_did' in stats
    assert 'total_requests' in stats
    assert 'success_rate' in stats
    assert stats['agent_name'] == "TestBot"

@patch('uaip.sdk.requests.Session.get')
def test_health_check_success(self, mock_get, sdk):
    """Test successful health check"""
    mock_get.return_value = Mock(
        status_code=200,
        json=lambda: {"status": "healthy"}
    )
    
    result = sdk.health_check()
    
    assert result["gateway_status"] == "healthy"

@patch('uaip.sdk.requests.Session.get')
def test_health_check_failure(self, mock_get, sdk):
    """Test failed health check"""
    mock_get.side_effect = Exception("Connection error")
    
    result = sdk.health_check()
    
    assert result["gateway_status"] == "unhealthy"
    assert "error" in result
class TestSDKEdgeCases:
"""Test edge cases and error handling"""
@pytest.fixture
def sdk(self):
    return UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )

def test_maximum_amount(self, sdk):
    """Test handling of maximum allowed amount"""
    # Should accept amounts up to 1 billion
    result = sdk._validate_amount(Decimal("1000000000"))
    assert result == Decimal("1000000000")

def test_amount_exceeds_maximum(self, sdk):
    """Test rejection of amounts over maximum"""
    with pytest.raises(ValueError, match="exceeds maximum"):
        sdk._validate_amount(Decimal("1000000001"))

def test_minimum_amount(self, sdk):
    """Test handling of minimum allowed amount"""
    result = sdk._validate_amount(Decimal("0.01"))
    assert result == Decimal("0.01")

def test_amount_below_minimum(self, sdk):
    """Test rejection of amounts below minimum"""
    with pytest.raises(ValueError, match="below minimum"):
        sdk._validate_amount(Decimal("0.001"))

@patch('uaip.sdk.requests.Session.post')
def test_rate_limit_handling(self, mock_post, sdk):
    """Test handling of rate limit responses"""
    mock_post.return_value = Mock(
        status_code=429,
        headers={'Retry-After': '2'},
        json=lambda: {"detail": "Rate limit exceeded"}
    )
    
    with pytest.raises(RuntimeError, match="Rate limit"):
        sdk.call_agent(
            task="Test",
            amount=50.0,
            intent="Testing",
            chain="BASE"
        )

def test_context_manager(self, sdk):
    """Test SDK as context manager"""
    with sdk as s:
        assert s.agent_name == "TestBot"
    # Should cleanup properly
class TestSDKSecurity:
"""Test security features"""
@pytest.fixture
def sdk(self):
    return UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )

def test_nonce_generation(self, sdk):
    """Test that nonces are unique"""
    nonce1 = sdk._generate_nonce()
    nonce2 = sdk._generate_nonce()
    
    assert nonce1 != nonce2
    assert len(nonce1) == 32  # UUID hex length

def test_signature_generation(self, sdk):
    """Test that signatures are generated"""
    data = {"test": "data"}
    signature = sdk._sign_data(data)
    
    assert signature is not None
    assert len(signature) > 0
    assert isinstance(signature, str)

def test_did_generation(self, sdk):
    """Test DID format"""
    assert sdk.did.startswith("did:uaip:")
    assert "testcorp" in sdk.did.lower()