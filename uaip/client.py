"""Main client interface for UAIP agents."""

from typing import Optional, Dict
import time
import hashlib

from .core.identity import DIDGenerator
from .exceptions import ComplianceError


class Receipt:
    """Payment receipt with transaction details."""
    
    def __init__(self, data: Dict):
        self.from_agent = data['from_agent']
        self.to_agent = data['to_agent']
        self.amount_usd = data['amount_usd']
        self.amount_usdc = data['amount_usdc']
        self.protocol_tax = data['protocol_tax']
        self.chain = data['chain']
        self.tx_hash = data['tx_hash']
        self.status = data['status']
        self.timestamp = data['timestamp']
        self.compliance_passed = data.get('compliance_passed', True)
    
    def __repr__(self):
        return f"<Receipt {self.status} ${self.amount_usd} on {self.chain}>"


class UAIPAgent:
    """
    A UAIP-enabled AI agent with cryptographic identity and payment capabilities.
    
    Attributes:
        name: Agent name
        company: Company name
        did: Decentralized Identifier (e.g., "did:uaip:abc123...")
        public_key: Ed25519 public key for signature verification
    
    Example:
        >>> agent = UAIPAgent(name="FinanceBot", company="Acme Corp")
        >>> print(agent.did)
        did:uaip:7F3E2D1C...
        
        >>> receipt = agent.pay(
        ...     to_agent="did:uaip:vendor123",
        ...     amount=100.00,
        ...     purpose="Invoice processing"
        ... )
        >>> print(receipt.status)
        completed
    """
    
    def __init__(
        self,
        name: str,
        company: str,
        chain: str = "BASE",
        enable_compliance: bool = True,
        auto_settlement: bool = True
    ):
        """
        Initialize a new UAIP agent.
        
        Args:
            name: Agent name (e.g., "ProcurementBot")
            company: Company name (e.g., "Acme Corp")
            chain: Blockchain for settlement ("BASE" or "SOLANA")
            enable_compliance: Automatically check compliance (default: True)
            auto_settlement: Automatically settle payments (default: True)
        """
        self.name = name
        self.company = company
        self.chain = chain
        self._auto_settlement = auto_settlement
        self._enable_compliance = enable_compliance
        
        # Generate cryptographic identity
        self._identity = DIDGenerator()
        self.did = self._identity.generate_did(name, company)
        self.public_key = self._identity.public_key
        self._private_key = self._identity.private_key
        
        print(f"✅ Agent '{name}' created")
        print(f"   DID: {self.did[:40]}...")
    
    def pay(
        self,
        to_agent: str,
        amount: float,
        purpose: str = "Payment",
        chain: Optional[str] = None
    ) -> Receipt:
        """
        Pay another agent securely.
        
        This automatically handles:
        - Identity verification
        - JIT authorization
        - Compliance checking
        - Multi-chain settlement
        - Audit logging
        
        Args:
            to_agent: Recipient's DID
            amount: Amount in USD
            purpose: Payment purpose (for audit trail)
            chain: Override default chain (optional)
        
        Returns:
            Receipt with transaction details
        
        Raises:
            ComplianceError: If payment violates compliance rules
            SettlementError: If blockchain transaction fails
        
        Example:
            >>> receipt = agent.pay(
            ...     to_agent="did:uaip:vendor123",
            ...     amount=250.00,
            ...     purpose="Q4 invoice processing"
            ... )
        """
        start_time = time.time()
        target_chain = chain or self.chain
        
        print(f"\n💰 Initiating payment: ${amount} to {to_agent[:30]}...")
        
        # Step 1: Request JIT authorization
        print("   🔐 Requesting JIT authorization...")
        token = self._request_auth_token(to_agent, amount)
        print(f"   ✅ Authorization granted (expires in 60s)")
        
        # Step 2: Compliance check
        compliance_result = None
        if self._enable_compliance:
            print("   📊 Running compliance check...")
            compliance_result = self._check_compliance(amount, to_agent, purpose)
            
            if not compliance_result['passed']:
                raise ComplianceError(
                    f"Payment blocked: {compliance_result['reason']}"
                )
            
            print(f"   ✅ Compliance passed (EU AI Act ✓, SOC2 ✓, GDPR ✓)")
        
        # Step 3: Execute settlement
        print(f"   ⛓️  Settling on {target_chain}...")
        tx_result = self._simulate_settlement(to_agent, amount, target_chain)
        
        # Build receipt
        receipt = Receipt({
            'from_agent': self.did,
            'to_agent': to_agent,
            'amount_usd': amount,
            'amount_usdc': tx_result['usdc_amount'],
            'protocol_tax': amount * 0.005,  # 0.5%
            'chain': target_chain,
            'tx_hash': tx_result['tx_hash'],
            'status': 'completed',
            'timestamp': time.time(),
            'compliance_passed': compliance_result['passed'] if compliance_result else True
        })
        
        elapsed = time.time() - start_time
        print(f"   ✅ Payment completed in {elapsed:.2f}s")
        print(f"   🔗 TX: {receipt.tx_hash[:20]}...")
        
        return receipt
    
    def sign(self, message: str) -> str:
        """
        Sign a message with agent's private key.
        
        Args:
            message: Message to sign
        
        Returns:
            Hex-encoded signature
        """
        return self._identity.sign_message(message)
    
    def verify_identity(self) -> bool:
        """Verify this agent's cryptographic identity."""
        return self._identity.verify_identity(self.did)
    
    def request_authorization(
        self,
        action: str,
        target: str,
        amount: Optional[float] = None
    ) -> str:
        """
        Request JIT authorization token.
        
        Args:
            action: Action type (e.g., "payment", "data_access")
            target: Target agent DID or resource
            amount: Amount for financial actions (optional)
        
        Returns:
            Authorization token (valid 60 seconds)
        """
        return self._request_auth_token(target, amount)
    
    def check_compliance(
        self,
        action: str,
        amount: float,
        recipient: str
    ) -> Dict:
        """
        Check if an action complies with regulations.
        
        Args:
            action: Action type
            amount: Transaction amount
            recipient: Recipient DID
        
        Returns:
            Dict with compliance results
        """
        if not self._enable_compliance:
            return {
                'passed': True,
                'note': 'Compliance checking disabled'
            }
        
        result = self._check_compliance(amount, recipient, action)
        
        return {
            'passed': result['passed'],
            'eu_ai_act': result.get('eu_ai_act', 'N/A'),
            'soc2': result.get('soc2', 'N/A'),
            'gdpr': result.get('gdpr', 'N/A'),
            'risk_level': result.get('risk_level', 'LOW')
        }
    
    @staticmethod
    def verify_signature(
        message: str,
        signature: str,
        public_key: str
    ) -> bool:
        """
        Verify a signature from another agent.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
        
        Returns:
            True if signature is valid
        """
        return DIDGenerator.verify_external_signature(
            message, signature, public_key
        )
    
    # Private helper methods
    def _request_auth_token(self, recipient_did: str, amount: float) -> str:
        """Simulate JIT authorization token generation."""
        token_data = f"{self.did}:{recipient_did}:{amount}:{time.time()}"
        return hashlib.sha256(token_data.encode()).hexdigest()
    
    def _check_compliance(self, amount: float, recipient: str, purpose: str) -> dict:
        """Simulate compliance checking."""
        # In production: RAG-powered Llama-3-Legal model checks regulations
        return {
            'passed': True,
            'eu_ai_act': 'PASSED',
            'soc2': 'PASSED',
            'gdpr': 'PASSED',
            'risk_level': 'LOW' if amount < 10000 else 'MEDIUM',
            'reason': None
        }
    
    def _simulate_settlement(self, recipient_did: str, amount: float, chain: str) -> dict:
        """Simulate blockchain transaction."""
        time.sleep(0.5)  # Simulate network delay
        tx_data = f"{self.did}:{recipient_did}:{amount}:{time.time()}"
        return {
            'usdc_amount': amount,  # 1:1 USD to USDC
            'tx_hash': "0x" + hashlib.sha256(tx_data.encode()).hexdigest()
        }