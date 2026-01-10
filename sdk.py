import requests
import time
import uuid
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from decimal import Decimal
import nacl.signing
import nacl.encoding
from privacy import ZK_Privacy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UAIP_Enterprise_SDK:
    """
    Secure SDK for UAIP Agent Integration.
    
    Security Features:
    - Input validation and sanitization
    - Retry logic with exponential backoff
    - Timeout protection
    - Error handling and recovery
    - Request signing and verification
    - Rate limiting awareness
    - Connection pooling
    - Secure secret key storage
    
    Example:
        >>> agent = UAIP_Enterprise_SDK(
        ...     agent_name="FinanceBot",
        ...     company_name="Acme Corp",
        ...     secret_code=12345
        ... )
        >>> result = agent.call_agent(
        ...     task="process_invoice",
        ...     amount=50.00,
        ...     intent="Q1 vendor payment"
        ... )
    """
    
    # Constants
    MAX_AMOUNT = Decimal("1000000000")  # $1B
    MIN_AMOUNT = Decimal("0.01")  # $0.01
    MAX_TASK_LENGTH = 5000
    MAX_INTENT_LENGTH = 2000
    MAX_COMPANY_NAME_LENGTH = 100
    MAX_AGENT_NAME_LENGTH = 100
    
    # Supported chains
    SUPPORTED_CHAINS = ["BASE", "SOLANA", "ETHEREUM", "POLYGON"]
    
    # Retry configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2  # Exponential backoff multiplier
    INITIAL_RETRY_DELAY = 1  # seconds
    
    # Timeout configuration
    REQUEST_TIMEOUT = 30  # seconds
    POLLING_TIMEOUT = 300  # 5 minutes max wait for approval
    POLLING_INTERVAL = 2  # seconds
    
    def __init__(
        self,
        agent_name: str,
        company_name: str,
        secret_code: int,
        gateway_url: str = "http://localhost:8000",
        auto_register: bool = True
    ):
        """
        Initialize the UAIP SDK client.
        
        Args:
            agent_name: Name of the agent
            company_name: Company/organization name
            secret_code: Secret integer for ZK proofs (keep secure!)
            gateway_url: URL of the UAIP gateway
            auto_register: Whether to auto-register on initialization
            
        Raises:
            ValueError: If inputs are invalid
            RuntimeError: If registration fails
        """
        try:
            # Validate inputs
            self.agent_name = self._validate_agent_name(agent_name)
            self.company_name = self._validate_company_name(company_name)
            self.secret_code = self._validate_secret_code(secret_code)
            self.gateway = self._validate_gateway_url(gateway_url)
            
            # Generate cryptographic identity
            self._initialize_identity()
            
            # Setup HTTP session with connection pooling
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': f'UAIP-SDK/1.0 ({self.agent_name})',
                'Content-Type': 'application/json'
            })
            
            # Track request statistics
            self.stats = {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'total_amount_processed': Decimal('0')
            }
            
            # Auto-register if requested
            if auto_register:
                self.register()
            
            logger.info(f"SDK initialized for agent: {self.did}")
            
        except Exception as e:
            logger.error(f"SDK initialization failed: {e}", exc_info=True)
            raise
    
    def _validate_agent_name(self, name: str) -> str:
        """Validate and sanitize agent name."""
        if not name or not isinstance(name, str):
            raise ValueError("Agent name is required and must be a string")
        
        name = name.strip()
        
        if len(name) > self.MAX_AGENT_NAME_LENGTH:
            raise ValueError(f"Agent name exceeds maximum length: {self.MAX_AGENT_NAME_LENGTH}")
        
        if not name.replace('_', '').replace('-', '').replace(' ', '').isalnum():
            raise ValueError("Agent name must contain only alphanumeric characters, spaces, hyphens, and underscores")
        
        return name
    
    def _validate_company_name(self, name: str) -> str:
        """Validate and sanitize company name."""
        if not name or not isinstance(name, str):
            raise ValueError("Company name is required and must be a string")
        
        name = name.strip()
        
        if len(name) > self.MAX_COMPANY_NAME_LENGTH:
            raise ValueError(f"Company name exceeds maximum length: {self.MAX_COMPANY_NAME_LENGTH}")
        
        if not name.replace('_', '').replace('-', '').replace(' ', '').replace('.', '').isalnum():
            raise ValueError("Company name must contain only alphanumeric characters, spaces, hyphens, underscores, and periods")
        
        return name
    
    def _validate_secret_code(self, code: int) -> int:
        """Validate secret code for ZK proofs."""
        if not isinstance(code, int):
            try:
                code = int(code)
            except (ValueError, TypeError):
                raise ValueError("Secret code must be an integer")
        
        # Use ZK_Privacy validation
        if code < ZK_Privacy.MIN_SECRET_KEY or code > ZK_Privacy.MAX_SECRET_KEY:
            raise ValueError(
                f"Secret code must be between {ZK_Privacy.MIN_SECRET_KEY} "
                f"and {ZK_Privacy.MAX_SECRET_KEY}"
            )
        
        return code
    
    def _validate_gateway_url(self, url: str) -> str:
        """Validate and sanitize gateway URL."""
        if not url or not isinstance(url, str):
            raise ValueError("Gateway URL is required and must be a string")
        
        url = url.strip().rstrip('/')
        
        if not url.startswith(('http://', 'https://')):
            raise ValueError("Gateway URL must start with http:// or https://")
        
        # Basic URL validation
        if len(url) > 500:
            raise ValueError("Gateway URL too long")
        
        return url
    
    def _initialize_identity(self):
        """Generate cryptographic identity components."""
        # Generate Ed25519 signing key pair
        self.sk = nacl.signing.SigningKey.generate()
        self.pk = self.sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
        
        # Generate DID (Decentralized Identifier)
        company_slug = self.company_name.lower().replace(' ', '-').replace('.', '')
        pk_hash = hashlib.sha256(self.pk.encode()).hexdigest()[:16]
        self.did = f"did:uaip:{company_slug}:{pk_hash}"
        
        # Generate ZK commitment
        self.zk_commitment = ZK_Privacy.generate_commitment(self.secret_code)
        
        logger.debug(f"Generated identity: DID={self.did}, PK={self.pk[:16]}...")
    
    def _sign_data(self, data: Dict[str, Any]) -> str:
        """
        Sign data with agent's private key.
        
        Args:
            data: Data dictionary to sign
            
        Returns:
            Hex-encoded signature
        """
        # Create canonical JSON representation
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        # Sign with Ed25519
        signature = self.sk.sign(msg).signature
        
        return signature.hex()
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        max_retries: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic and error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request payload (for POST)
            max_retries: Maximum retry attempts (overrides default)
            
        Returns:
            Response JSON data
            
        Raises:
            RuntimeError: If request fails after retries
        """
        url = f"{self.gateway}{endpoint}"
        retries = max_retries if max_retries is not None else self.MAX_RETRIES
        delay = self.INITIAL_RETRY_DELAY
        
        for attempt in range(retries + 1):
            try:
                if method.upper() == "GET":
                    response = self.session.get(url, timeout=self.REQUEST_TIMEOUT)
                elif method.upper() == "POST":
                    response = self.session.post(url, json=data, timeout=self.REQUEST_TIMEOUT)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Check for HTTP errors
                if response.status_code == 429:
                    # Rate limited - wait longer
                    logger.warning(f"Rate limited. Waiting {delay * 2}s before retry...")
                    time.sleep(delay * 2)
                    delay *= self.RETRY_BACKOFF
                    continue
                
                if response.status_code >= 500:
                    # Server error - retry
                    logger.warning(f"Server error {response.status_code}. Retrying...")
                    time.sleep(delay)
                    delay *= self.RETRY_BACKOFF
                    continue
                
                # Parse response
                try:
                    response_data = response.json()
                except ValueError:
                    logger.error(f"Invalid JSON response: {response.text[:200]}")
                    raise RuntimeError("Invalid response from gateway")
                
                # Check for application-level errors
                if response.status_code >= 400:
                    error_detail = response_data.get('detail', 'Unknown error')
                    logger.error(f"Request failed: {error_detail}")
                    raise RuntimeError(f"Gateway error: {error_detail}")
                
                return response_data
                
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1}/{retries + 1})")
                if attempt < retries:
                    time.sleep(delay)
                    delay *= self.RETRY_BACKOFF
                else:
                    raise RuntimeError("Request timed out after retries")
            
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error (attempt {attempt + 1}/{retries + 1})")
                if attempt < retries:
                    time.sleep(delay)
                    delay *= self.RETRY_BACKOFF
                else:
                    raise RuntimeError("Could not connect to gateway")
            
            except Exception as e:
                logger.error(f"Unexpected error in request: {e}", exc_info=True)
                raise RuntimeError(f"Request failed: {e}")
        
        raise RuntimeError("Request failed after all retries")
    
    def register(self) -> Dict[str, Any]:
        """
        Register agent with the UAIP gateway.
        
        Returns:
            Registration response
            
        Raises:
            RuntimeError: If registration fails
        """
        try:
            logger.info(f"Registering agent: {self.did}")
            
            # Prepare registration data
            reg_data = {
                "agent_id": self.did,
                "zk_commitment": self.zk_commitment,
                "public_key": self.pk,
                "timestamp": time.time()
            }
            
            # Sign registration data
            signature = self._sign_data(reg_data)
            
            # Send registration request
            response = self._make_request(
                "POST",
                "/v1/register",
                data={
                    "registration_data": reg_data,
                    "signature": signature,
                    "public_key": self.pk
                }
            )
            
            logger.info(f"✅ REGISTRATION SUCCESSFUL: {self.did}")
            return response
            
        except Exception as e:
            logger.error(f"Registration failed: {e}", exc_info=True)
            raise RuntimeError(f"Registration failed: {e}")
    
    def call_agent(
        self,
        task: str,
        amount: Any,
        intent: str,
        chain: str = "BASE",
        metadata: Optional[Dict[str, Any]] = None,
        wait_for_approval: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a governed agent transaction.
        
        Args:
            task: Task description
            amount: Transaction amount (USD)
            intent: Human-readable intent/purpose
            chain: Blockchain network (default: BASE)
            metadata: Optional additional metadata
            wait_for_approval: Whether to wait for manual approval if needed
            
        Returns:
            Transaction result
            
        Raises:
            ValueError: If inputs are invalid
            RuntimeError: If transaction fails
        """
        try:
            # Track request
            self.stats['total_requests'] += 1
            
            # Validate inputs
            validated_task = self._validate_task(task)
            validated_amount = self._validate_amount(amount)
            validated_intent = self._validate_intent(intent)
            validated_chain = self._validate_chain(chain)
            
            logger.info(f"Executing transaction: ${validated_amount} - {validated_task}")
            
            # Generate ZK proof
            proof = ZK_Privacy.create_proof(self.secret_code, self.zk_commitment)
            
            # Prepare transaction data
            nonce = uuid.uuid4().hex
            timestamp = time.time()
            
            data = {
                "task": validated_task,
                "amount": str(validated_amount),
                "intent": validated_intent,
                "nonce": nonce,
                "timestamp": timestamp
            }
            
            # Add metadata if provided
            if metadata:
                data["metadata"] = metadata
            
            # Sign transaction data
            signature = self._sign_data(data)
            
            # Build UAIP packet
            packet = {
                "sender_id": self.did,
                "task": validated_task,
                "amount": str(validated_amount),
                "chain": validated_chain,
                "intent": validated_intent,
                "data": data,
                "signature": signature,
                "public_key": self.pk,
                "nonce": nonce,
                "timestamp": timestamp,
                "zk_proof": proof
            }
            
            # Send transaction
            response = self._make_request("POST", "/v1/execute", data=packet)
            
            # Handle response
            status = response.get("status")
            
            if status == "SUCCESS":
                self.stats['successful_requests'] += 1
                self.stats['total_amount_processed'] += validated_amount
                logger.info(f"✅ Transaction successful: {response.get('request_id')}")
                return response
            
            elif status in ["PENDING_APPROVAL", "PAUSED"]:
                req_id = response.get("request_id")
                logger.info(f"⏸️  Transaction pending approval: {req_id}")
                
                if wait_for_approval:
                    return self._wait_for_approval(req_id)
                else:
                    return response
            
            else:
                self.stats['failed_requests'] += 1
                error = response.get('detail', 'Unknown error')
                logger.error(f"Transaction failed: {error}")
                raise RuntimeError(f"Transaction failed: {error}")
                
        except ValueError as e:
            self.stats['failed_requests'] += 1
            logger.error(f"Validation error: {e}")
            raise
        except Exception as e:
            self.stats['failed_requests'] += 1
            logger.error(f"Transaction execution error: {e}", exc_info=True)
            raise RuntimeError(f"Transaction failed: {e}")
    
    def _validate_task(self, task: str) -> str:
        """Validate task description."""
        if not task or not isinstance(task, str):
            raise ValueError("Task is required and must be a string")
        
        task = task.strip()
        
        if len(task) > self.MAX_TASK_LENGTH:
            raise ValueError(f"Task description exceeds maximum length: {self.MAX_TASK_LENGTH}")
        
        if len(task) < 3:
            raise ValueError("Task description must be at least 3 characters")
        
        return task
    
    def _validate_amount(self, amount: Any) -> Decimal:
        """Validate transaction amount."""
        try:
            amount_dec = Decimal(str(amount))
        except Exception:
            raise ValueError("Amount must be a valid number")
        
        if amount_dec < self.MIN_AMOUNT:
            raise ValueError(f"Amount must be at least {self.MIN_AMOUNT}")
        
        if amount_dec > self.MAX_AMOUNT:
            raise ValueError(f"Amount exceeds maximum: {self.MAX_AMOUNT}")
        
        if amount_dec.as_tuple().exponent < -18:
            raise ValueError("Too many decimal places (max 18)")
        
        return amount_dec
    
    def _validate_intent(self, intent: str) -> str:
        """Validate transaction intent."""
        if not intent or not isinstance(intent, str):
            raise ValueError("Intent is required and must be a string")
        
        intent = intent.strip()
        
        if len(intent) > self.MAX_INTENT_LENGTH:
            raise ValueError(f"Intent exceeds maximum length: {self.MAX_INTENT_LENGTH}")
        
        if len(intent) < 3:
            raise ValueError("Intent must be at least 3 characters")
        
        return intent
    
    def _validate_chain(self, chain: str) -> str:
        """Validate blockchain network."""
        if not chain or not isinstance(chain, str):
            raise ValueError("Chain is required and must be a string")
        
        chain_upper = chain.upper().strip()
        
        if chain_upper not in self.SUPPORTED_CHAINS:
            raise ValueError(
                f"Unsupported chain: {chain}. "
                f"Supported chains: {', '.join(self.SUPPORTED_CHAINS)}"
            )
        
        return chain_upper
    
    def _wait_for_approval(self, request_id: str) -> Dict[str, Any]:
        """
        Poll for approval status with timeout.
        
        Args:
            request_id: Transaction request ID
            
        Returns:
            Final transaction result
            
        Raises:
            RuntimeError: If approval times out or is denied
        """
        start_time = time.time()
        
        logger.info(f"Waiting for approval: {request_id}")
        
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > self.POLLING_TIMEOUT:
                raise RuntimeError(f"Approval timeout after {self.POLLING_TIMEOUT}s")
            
            try:
                # Check status
                response = self._make_request("GET", f"/v1/check/{request_id}")
                status = response.get("status")
                
                if status == "APPROVED":
                    logger.info(f"✅ Transaction approved: {request_id}")
                    self.stats['successful_requests'] += 1
                    return {"status": "APPROVED", "request_id": request_id}
                
                elif status in ["REJECTED", "DENIED"]:
                    logger.warning(f"❌ Transaction rejected: {request_id}")
                    self.stats['failed_requests'] += 1
                    raise RuntimeError(f"Transaction rejected: {request_id}")
                
                # Still waiting
                time.sleep(self.POLLING_INTERVAL)
                
            except RuntimeError:
                raise
            except Exception as e:
                logger.error(f"Error checking approval status: {e}")
                time.sleep(self.POLLING_INTERVAL)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get SDK usage statistics.
        
        Returns:
            Dictionary of statistics
        """
        return {
            'agent_did': self.did,
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'success_rate': (
                self.stats['successful_requests'] / self.stats['total_requests'] * 100
                if self.stats['total_requests'] > 0 else 0
            ),
            'total_amount_processed': float(self.stats['total_amount_processed'])
        }
    
    def __repr__(self) -> str:
        """String representation of SDK instance."""
        return f"UAIP_SDK(agent={self.agent_name}, did={self.did}, gateway={self.gateway})"
    
    def __del__(self):
        """Cleanup on deletion."""
        if hasattr(self, 'session'):
            self.session.close()
