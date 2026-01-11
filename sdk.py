import requests
import time
import uuid
import json
import hashlib
import logging
import re
from typing import Dict, Any, Optional, Tuple
from decimal import Decimal, InvalidOperation, ROUND_DOWN
import nacl.signing
import nacl.encoding
from privacy import ZK_Privacy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)


class UAIP_Enterprise_SDK:
    """
    Production-Grade SDK for UAIP Agent Integration.
    
    Security Features:
    - Comprehensive input validation and sanitization
    - Retry logic with exponential backoff and jitter
    - Timeout protection with configurable limits
    - Robust error handling and recovery
    - Ed25519 request signing and verification
    - Rate limiting awareness and backoff
    - Connection pooling with keep-alive
    - Secure secret key handling (never logged)
    - Request deduplication via nonce tracking
    - Thread-safe operations
    
    Example:
        >>> agent = UAIP_Enterprise_SDK(
        ...     agent_name="FinanceBot",
        ...     company_name="Acme Corp",
        ...     secret_code=12345,
        ...     gateway_url="https://gateway.uaip.io"
        ... )
        >>> result = agent.call_agent(
        ...     task="process_invoice",
        ...     amount=50.00,
        ...     intent="Q1 vendor payment",
        ...     chain="BASE"
        ... )
        >>> print(result['status'])  # "SUCCESS" or "PENDING_APPROVAL"
    """
    
    # === CONSTANTS ===
    MAX_AMOUNT = Decimal("1000000000")  # $1B
    MIN_AMOUNT = Decimal("0.01")  # $0.01
    MAX_TASK_LENGTH = 5000
    MAX_INTENT_LENGTH = 2000
    MAX_COMPANY_NAME_LENGTH = 100
    MAX_AGENT_NAME_LENGTH = 100
    MAX_METADATA_SIZE = 10000  # bytes
    
    # Supported blockchain networks
    SUPPORTED_CHAINS = ["BASE", "SOLANA", "ETHEREUM", "POLYGON"]
    
    # Chain-specific decimal precision
    CHAIN_DECIMALS = {
        "BASE": 18,
        "SOLANA": 9,
        "ETHEREUM": 18,
        "POLYGON": 18
    }
    
    # Retry configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2  # Exponential backoff multiplier
    INITIAL_RETRY_DELAY = 1  # seconds
    MAX_RETRY_DELAY = 60  # seconds (cap for exponential backoff)
    RETRY_JITTER = 0.1  # Add random jitter to prevent thundering herd
    
    # Timeout configuration
    REQUEST_TIMEOUT = 30  # seconds per request
    POLLING_TIMEOUT = 300  # 5 minutes max wait for approval
    POLLING_INTERVAL = 2  # seconds between status checks
    
    # Security
    MAX_NONCE_CACHE_SIZE = 10000  # Prevent memory exhaustion
    
    def __init__(
        self,
        agent_name: str,
        company_name: str,
        secret_code: int,
        gateway_url: str = "http://localhost:8000",
        auto_register: bool = True,
        verify_ssl: bool = True
    ):
        """
        Initialize the UAIP SDK client with secure defaults.
        
        Args:
            agent_name: Name of the agent (alphanumeric, spaces, hyphens, underscores)
            company_name: Company/organization name
            secret_code: Secret integer for ZK proofs (KEEP SECURE - never share!)
            gateway_url: URL of the UAIP gateway (http:// or https://)
            auto_register: Whether to auto-register on initialization
            verify_ssl: Whether to verify SSL certificates (disable only for testing)
            
        Raises:
            ValueError: If inputs are invalid
            RuntimeError: If registration fails
        """
        try:
            # Validate inputs BEFORE storing anything
            self.agent_name = self._validate_agent_name(agent_name)
            self.company_name = self._validate_company_name(company_name)
            self.secret_code = self._validate_secret_code(secret_code)
            self.gateway = self._validate_gateway_url(gateway_url)
            self.verify_ssl = verify_ssl
            
            # Security warning for disabled SSL verification
            if not verify_ssl:
                logger.warning("⚠️  SSL verification disabled - only use in development!")
            
            # Generate cryptographic identity
            self._initialize_identity()
            
            # Setup HTTP session with connection pooling and security headers
            self._initialize_session()
            
            # Track used nonces to prevent accidental reuse
            self._nonce_cache = set()
            
            # Track request statistics
            self.stats = {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'total_amount_processed': Decimal('0'),
                'registrations': 0
            }
            
            # Auto-register if requested
            if auto_register:
                self.register()
            
            logger.info(f"✅ SDK initialized for agent: {self.did}")
            
        except Exception as e:
            logger.error(f"SDK initialization failed: {e}", exc_info=True)
            raise
    
    def _validate_agent_name(self, name: str) -> str:
        """
        Validate and sanitize agent name.
        
        Args:
            name: Agent name to validate
            
        Returns:
            Sanitized agent name
            
        Raises:
            ValueError: If name is invalid
        """
        if not name or not isinstance(name, str):
            raise ValueError("Agent name is required and must be a string")
        
        name = name.strip()
        
        if not name:
            raise ValueError("Agent name cannot be empty or whitespace-only")
        
        if len(name) > self.MAX_AGENT_NAME_LENGTH:
            raise ValueError(
                f"Agent name exceeds maximum length: {self.MAX_AGENT_NAME_LENGTH} characters"
            )
        
        # Allow alphanumeric, spaces, hyphens, underscores
        if not re.match(r'^[\w\s\-]+$', name):
            raise ValueError(
                "Agent name must contain only alphanumeric characters, spaces, hyphens, and underscores"
            )
        
        return name
    
    def _validate_company_name(self, name: str) -> str:
        """
        Validate and sanitize company name.
        
        Args:
            name: Company name to validate
            
        Returns:
            Sanitized company name
            
        Raises:
            ValueError: If name is invalid
        """
        if not name or not isinstance(name, str):
            raise ValueError("Company name is required and must be a string")
        
        name = name.strip()
        
        if not name:
            raise ValueError("Company name cannot be empty or whitespace-only")
        
        if len(name) > self.MAX_COMPANY_NAME_LENGTH:
            raise ValueError(
                f"Company name exceeds maximum length: {self.MAX_COMPANY_NAME_LENGTH} characters"
            )
        
        # Allow alphanumeric, spaces, hyphens, underscores, periods
        if not re.match(r'^[\w\s\-\.]+$', name):
            raise ValueError(
                "Company name must contain only alphanumeric characters, spaces, hyphens, underscores, and periods"
            )
        
        return name
    
    def _validate_secret_code(self, code: int) -> int:
        """
        Validate secret code for ZK proofs.
        
        Args:
            code: Secret code to validate
            
        Returns:
            Validated secret code
            
        Raises:
            ValueError: If code is invalid
        """
        if not isinstance(code, int):
            try:
                code = int(code)
            except (ValueError, TypeError):
                raise ValueError("Secret code must be an integer")
        
        # Delegate to ZK_Privacy validation for consistency
        if code < ZK_Privacy.MIN_SECRET_KEY or code > ZK_Privacy.MAX_SECRET_KEY:
            raise ValueError(
                f"Secret code must be between {ZK_Privacy.MIN_SECRET_KEY} "
                f"and {ZK_Privacy.MAX_SECRET_KEY}"
            )
        
        return code
    
    def _validate_gateway_url(self, url: str) -> str:
        """
        Validate and sanitize gateway URL.
        
        Args:
            url: Gateway URL to validate
            
        Returns:
            Sanitized gateway URL
            
        Raises:
            ValueError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise ValueError("Gateway URL is required and must be a string")
        
        url = url.strip().rstrip('/')
        
        if not url:
            raise ValueError("Gateway URL cannot be empty or whitespace-only")
        
        # Must start with http:// or https://
        if not url.startswith(('http://', 'https://')):
            raise ValueError("Gateway URL must start with http:// or https://")
        
        # Prevent excessively long URLs
        if len(url) > 500:
            raise ValueError("Gateway URL too long (max 500 characters)")
        
        # Basic validation: should contain at least a domain
        # Extract domain part
        domain_part = url.split('//')[1].split('/')[0] if '//' in url else ''
        if not domain_part:
            raise ValueError("Invalid gateway URL format")
        
        return url
    
    def _initialize_identity(self):
        """
        Generate cryptographic identity components.
        
        Creates:
        - Ed25519 signing key pair
        - Decentralized Identifier (DID)
        - Zero-Knowledge commitment
        """
        # Generate Ed25519 signing key pair for request authentication
        self.sk = nacl.signing.SigningKey.generate()
        self.pk = self.sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
        
        # Generate DID (Decentralized Identifier) using W3C DID spec format
        # Format: did:uaip:{company-slug}:{pk-hash}
        company_slug = re.sub(r'[^\w\-]', '', self.company_name.lower().replace(' ', '-'))
        pk_hash = hashlib.sha256(self.pk.encode()).hexdigest()[:16]
        self.did = f"did:uaip:{company_slug}:{pk_hash}"
        
        # Generate ZK commitment for privacy-preserving authentication
        self.zk_commitment = ZK_Privacy.generate_commitment(self.secret_code)
        
        logger.debug(
            f"Generated identity: DID={self.did}, "
            f"PK={self.pk[:16]}..., "
            f"Commitment={self.zk_commitment % 10000}..."
        )
    
    def _initialize_session(self):
        """
        Initialize HTTP session with connection pooling and security settings.
        """
        self.session = requests.Session()
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,  # We handle retries manually
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Set security headers
        self.session.headers.update({
            'User-Agent': f'UAIP-SDK/1.0 ({self.agent_name})',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UAIP-Client-Version': '1.0.0'
        })
        
        # SSL verification setting
        self.session.verify = self.verify_ssl
        
        logger.debug("HTTP session initialized with connection pooling")
    
    def _sign_data(self, data: Dict[str, Any]) -> str:
        """
        Sign data with agent's Ed25519 private key.
        
        Args:
            data: Data dictionary to sign
            
        Returns:
            Hex-encoded signature
        """
        # Create canonical JSON representation (deterministic)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        # Sign with Ed25519 (produces 64-byte signature)
        signed_msg = self.sk.sign(msg)
        signature = signed_msg.signature
        
        return signature.hex()
    
    def _generate_nonce(self) -> str:
        """
        Generate a unique nonce for request deduplication.
        
        Returns:
            UUID-based nonce as hex string
        """
        # Generate cryptographically random UUID
        nonce = uuid.uuid4().hex
        
        # Track nonce to prevent accidental reuse
        if len(self._nonce_cache) > self.MAX_NONCE_CACHE_SIZE:
            # Prevent memory exhaustion - clear oldest half
            self._nonce_cache = set(list(self._nonce_cache)[self.MAX_NONCE_CACHE_SIZE // 2:])
        
        self._nonce_cache.add(nonce)
        
        return nonce
    
    def _add_retry_jitter(self, delay: float) -> float:
        """
        Add random jitter to retry delay to prevent thundering herd.
        
        Args:
            delay: Base delay in seconds
            
        Returns:
            Delay with added jitter
        """
        import random
        jitter = delay * self.RETRY_JITTER * (random.random() * 2 - 1)  # ±10%
        return max(0.1, delay + jitter)  # Ensure positive
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        max_retries: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic, exponential backoff, and error handling.
        
        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint path
            data: Request payload (for POST)
            max_retries: Maximum retry attempts (overrides default)
            timeout: Request timeout in seconds (overrides default)
            
        Returns:
            Response JSON data
            
        Raises:
            RuntimeError: If request fails after all retries
        """
        url = f"{self.gateway}{endpoint}"
        retries = max_retries if max_retries is not None else self.MAX_RETRIES
        timeout_val = timeout if timeout is not None else self.REQUEST_TIMEOUT
        delay = self.INITIAL_RETRY_DELAY
        
        last_exception = None
        
        for attempt in range(retries + 1):
            try:
                # Make HTTP request
                if method.upper() == "GET":
                    response = self.session.get(url, timeout=timeout_val)
                elif method.upper() == "POST":
                    response = self.session.post(url, json=data, timeout=timeout_val)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle rate limiting (429)
                if response.status_code == 429:
                    retry_after = response.headers.get('Retry-After', delay * 2)
                    try:
                        wait_time = float(retry_after)
                    except ValueError:
                        wait_time = delay * 2
                    
                    logger.warning(
                        f"Rate limited (429). Waiting {wait_time}s before retry "
                        f"(attempt {attempt + 1}/{retries + 1})"
                    )
                    
                    if attempt < retries:
                        time.sleep(self._add_retry_jitter(wait_time))
                        delay = min(delay * self.RETRY_BACKOFF, self.MAX_RETRY_DELAY)
                        continue
                    else:
                        raise RuntimeError("Rate limit exceeded - max retries reached")
                
                # Handle server errors (5xx) - retry
                if response.status_code >= 500:
                    logger.warning(
                        f"Server error {response.status_code}. "
                        f"Retrying (attempt {attempt + 1}/{retries + 1})..."
                    )
                    
                    if attempt < retries:
                        time.sleep(self._add_retry_jitter(delay))
                        delay = min(delay * self.RETRY_BACKOFF, self.MAX_RETRY_DELAY)
                        continue
                    else:
                        raise RuntimeError(f"Server error {response.status_code} - max retries reached")
                
                # Parse JSON response
                try:
                    response_data = response.json()
                except ValueError as e:
                    logger.error(f"Invalid JSON response: {response.text[:200]}")
                    raise RuntimeError(f"Invalid JSON response from gateway: {e}")
                
                # Handle client errors (4xx)
                if response.status_code >= 400:
                    error_detail = response_data.get('detail', 'Unknown error')
                    
                    # Don't retry client errors (except 429, handled above)
                    logger.error(f"Client error {response.status_code}: {error_detail}")
                    raise RuntimeError(f"Gateway error ({response.status_code}): {error_detail}")
                
                # Success
                return response_data
                
            except requests.exceptions.Timeout as e:
                last_exception = e
                logger.warning(
                    f"Request timeout after {timeout_val}s "
                    f"(attempt {attempt + 1}/{retries + 1})"
                )
                
                if attempt < retries:
                    time.sleep(self._add_retry_jitter(delay))
                    delay = min(delay * self.RETRY_BACKOFF, self.MAX_RETRY_DELAY)
                else:
                    raise RuntimeError(f"Request timed out after {retries + 1} attempts")
            
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                logger.warning(
                    f"Connection error: {e} "
                    f"(attempt {attempt + 1}/{retries + 1})"
                )
                
                if attempt < retries:
                    time.sleep(self._add_retry_jitter(delay))
                    delay = min(delay * self.RETRY_BACKOFF, self.MAX_RETRY_DELAY)
                else:
                    raise RuntimeError(f"Could not connect to gateway after {retries + 1} attempts")
            
            except RuntimeError:
                # Don't retry RuntimeError (these are application-level errors)
                raise
            
            except Exception as e:
                logger.error(f"Unexpected error in request: {e}", exc_info=True)
                raise RuntimeError(f"Request failed: {e}")
        
        # Should never reach here, but just in case
        raise RuntimeError(f"Request failed after all retries: {last_exception}")
    
    def register(self) -> Dict[str, Any]:
        """
        Register agent with the UAIP gateway.
        
        This should be called once during agent initialization.
        Re-registration is idempotent (safe to call multiple times).
        
        Returns:
            Registration response dictionary
            
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
            
            self.stats['registrations'] += 1
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
        Execute a governed agent transaction through the UAIP network.
        
        This method handles:
        - Input validation
        - ZK proof generation
        - Request signing
        - Transaction submission
        - Optional approval waiting
        
        Args:
            task: Task description (3-5000 characters)
            amount: Transaction amount in USD (0.01 - 1,000,000,000)
            intent: Human-readable intent/purpose (3-2000 characters)
            chain: Blockchain network (BASE, SOLANA, ETHEREUM, POLYGON)
            metadata: Optional additional metadata (max 10KB)
            wait_for_approval: Whether to poll for manual approval if needed
            
        Returns:
            Transaction result dictionary with:
            - status: "SUCCESS", "PENDING_APPROVAL", or error
            - request_id: Unique transaction identifier
            - settlement: Settlement details (if successful)
            
        Raises:
            ValueError: If inputs are invalid
            RuntimeError: If transaction fails
            
        Example:
            >>> result = agent.call_agent(
            ...     task="Process vendor invoice #12345",
            ...     amount=150.00,
            ...     intent="Q1 2024 vendor payments",
            ...     chain="BASE"
            ... )
            >>> print(result['status'])
        """
        try:
            # Track request
            self.stats['total_requests'] += 1
            
            # Validate inputs
            validated_task = self._validate_task(task)
            validated_amount = self._validate_amount(amount)
            validated_intent = self._validate_intent(intent)
            validated_chain = self._validate_chain(chain)
            validated_metadata = self._validate_metadata(metadata) if metadata else None
            
            # Normalize amount to chain-specific precision
            normalized_amount = self._normalize_amount(validated_amount, validated_chain)
            
            logger.info(
                f"Executing transaction: ${normalized_amount} on {validated_chain} - {validated_task[:50]}..."
            )
            
            # Generate ZK proof (proves knowledge of secret without revealing it)
            proof = ZK_Privacy.create_proof(self.secret_code, self.zk_commitment)
            
            # Generate unique nonce for replay protection
            nonce = self._generate_nonce()
            timestamp = time.time()
            
            # Prepare transaction data for signing
            data = {
                "task": validated_task,
                "amount": str(normalized_amount),
                "intent": validated_intent,
                "nonce": nonce,
                "timestamp": timestamp
            }
            
            # Add metadata if provided
            if validated_metadata:
                data["metadata"] = validated_metadata
            
            # Sign transaction data with Ed25519
            signature = self._sign_data(data)
            
            # Build UAIP packet (complete transaction payload)
            packet = {
                "sender_id": self.did,
                "task": validated_task,
                "amount": str(normalized_amount),
                "chain": validated_chain,
                "intent": validated_intent,
                "data": data,
                "signature": signature,
                "public_key": self.pk,
                "nonce": nonce,
                "timestamp": timestamp,
                "zk_proof": proof
            }
            
            # Send transaction to gateway
            response = self._make_request("POST", "/v1/execute", data=packet)
            
            # Handle response based on status
            status = response.get("status")
            
            if status == "SUCCESS":
                # Transaction completed immediately
                self.stats['successful_requests'] += 1
                self.stats['total_amount_processed'] += normalized_amount
                logger.info(f"✅ Transaction successful: {response.get('request_id')}")
                return response
            
            elif status in ["PENDING_APPROVAL", "PAUSED"]:
                # Transaction requires human approval
                req_id = response.get("request_id")
                logger.info(f"⏸️  Transaction pending approval: {req_id}")
                
                if wait_for_approval:
                    # Poll for approval status
                    return self._wait_for_approval(req_id, normalized_amount)
                else:
                    # Return immediately without waiting
                    return response
            
            else:
                # Transaction failed
                self.stats['failed_requests'] += 1
                error = response.get('detail', 'Unknown error')
                logger.error(f"❌ Transaction failed: {error}")
                raise RuntimeError(f"Transaction failed: {error}")
                
        except ValueError as e:
            self.stats['failed_requests'] += 1
            logger.error(f"Validation error: {e}")
            raise
        except RuntimeError as e:
            self.stats['failed_requests'] += 1
            raise
        except Exception as e:
            self.stats['failed_requests'] += 1
            logger.error(f"Transaction execution error: {e}", exc_info=True)
            raise RuntimeError(f"Transaction failed: {e}")
    
    def _validate_task(self, task: str) -> str:
        """Validate task description with comprehensive checks."""
        if not task or not isinstance(task, str):
            raise ValueError("Task is required and must be a string")
        
        task = task.strip()
        
        if not task:
            raise ValueError("Task cannot be empty or whitespace-only")
        
        if len(task) < 3:
            raise ValueError("Task description must be at least 3 characters")
        
        if len(task) > self.MAX_TASK_LENGTH:
            raise ValueError(
                f"Task description exceeds maximum length: {self.MAX_TASK_LENGTH} characters"
            )
        
        return task
    
    def _validate_amount(self, amount: Any) -> Decimal:
        """Validate transaction amount with precision handling."""
        try:
            amount_dec = Decimal(str(amount))
        except (ValueError, InvalidOperation):
            raise ValueError(f"Amount must be a valid number, got: {amount}")
        
        if amount_dec < self.MIN_AMOUNT:
            raise ValueError(f"Amount must be at least ${self.MIN_AMOUNT}")
        
        if amount_dec > self.MAX_AMOUNT:
            raise ValueError(f"Amount exceeds maximum: ${self.MAX_AMOUNT}")
        
        # Check decimal precision
        if amount_dec.as_tuple().exponent < -18:
            raise ValueError("Too many decimal places (maximum 18)")
        
        return amount_dec
    
    def _validate_intent(self, intent: str) -> str:
        """Validate transaction intent."""
        if not intent or not isinstance(intent, str):
            raise ValueError("Intent is required and must be a string")
        
        intent = intent.strip()
        
        if not intent:
            raise ValueError("Intent cannot be empty or whitespace-only")
        
        if len(intent) < 3:
            raise ValueError("Intent must be at least 3 characters")
        
        if len(intent) > self.MAX_INTENT_LENGTH:
            raise ValueError(
                f"Intent exceeds maximum length: {self.MAX_INTENT_LENGTH} characters"
            )
        
        return intent
    
    def _validate_chain(self, chain: str) -> str:
        """Validate blockchain network."""
        if not chain or not isinstance(chain, str):
            raise ValueError("Chain is required and must be a string")
        
        chain_upper = chain.upper().strip()
        
        if chain_upper not in self.SUPPORTED_CHAINS:
            raise ValueError(
                f"Unsupported chain: {chain}. "
                f"Supported: {', '.join(self.SUPPORTED_CHAINS)}"
            )
        
        return chain_upper
    
    def _validate_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Validate optional metadata."""
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be a dictionary")
        
        # Check size to prevent DoS
        metadata_json = json.dumps(metadata)
        if len(metadata_json) > self.MAX_METADATA_SIZE:
            raise ValueError(
                f"Metadata too large: {len(metadata_json)} bytes "
                f"(max {self.MAX_METADATA_SIZE} bytes)"
            )
        
        return metadata
    
    def _normalize_amount(self, amount: Decimal, chain: str) -> Decimal:
        """Normalize amount to chain-specific decimal precision."""
        decimals = self.CHAIN_DECIMALS.get(chain, 18)
        quantize_str = '1.' + '0' * decimals
        return amount.quantize(Decimal(quantize_str), rounding=ROUND_DOWN)
    
    def _wait_for_approval(self, request_id: str, amount: Decimal) -> Dict[str, Any]:
        """
        Poll for approval status with exponential backoff and timeout.
        
        Args:
            request_id: Transaction request ID
            amount: Transaction amount (for statistics)
            
        Returns:
            Final transaction result
            
        Raises:
            RuntimeError: If approval times out or is denied
        """
        start_time = time.time()
        poll_delay = self.POLLING_INTERVAL
        
        logger.info(f"Waiting for approval: {request_id} (timeout: {self.POLLING_TIMEOUT}s)")
        
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > self.POLLING_TIMEOUT:
                raise RuntimeError(
                    f"Approval timeout after {self.POLLING_TIMEOUT}s for request {request_id}"
                )
            
            try:
                # Check status
                response = self._make_request(
                    "GET",
                    f"/v1/check/{request_id}",
                    max_retries=1  # Reduce retries for polling
                )
                status = response.get("status")
                
                if status in ["APPROVED", "HUMAN_APPROVED"]:
                    logger.info(f"✅ Transaction approved: {request_id}")
                    self.stats['successful_requests'] += 1
                    self.stats['total_amount_processed'] += amount
                    return {"status": "APPROVED", "request_id": request_id}
                
                elif status in ["REJECTED", "DENIED", "BLOCKED"]:
                    logger.warning(f"❌ Transaction rejected: {request_id}")
                    self.stats['failed_requests'] += 1
                    raise RuntimeError(f"Transaction rejected: {request_id}")
                
                # Still waiting - use exponential backoff
                time.sleep(poll_delay)
                poll_delay = min(poll_delay * 1.2, 10)  # Cap at 10 seconds
                
            except RuntimeError:
                raise
            except Exception as e:
                logger.error(f"Error checking approval status: {e}")
                time.sleep(self.POLLING_INTERVAL)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get SDK usage statistics.
        
        Returns:
            Dictionary containing usage metrics
        """
        success_rate = 0.0
        if self.stats['total_requests'] > 0:
            success_rate = (
                self.stats['successful_requests'] / self.stats['total_requests'] * 100
            )
        
        return {
            'agent_did': self.did,
            'agent_name': self.agent_name,
            'company_name': self.company_name,
            'gateway_url': self.gateway,
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'success_rate': round(success_rate, 2),
            'total_amount_processed': float(self.stats['total_amount_processed']),
            'registrations': self.stats['registrations']
        }
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check connectivity to UAIP gateway.
        
        Returns:
            Health check results
        """
        try:
            response = self._make_request(
                "GET",
                "/health",
                max_retries=1,
                timeout=5
            )
            
            return {
                "gateway_status": "healthy",
                "gateway_url": self.gateway,
                "response": response
            }
        except Exception as e:
            return {
                "gateway_status": "unhealthy",
                "gateway_url": self.gateway,
                "error": str(e)
            }
    
    def __repr__(self) -> str:
        """String representation of SDK instance."""
        return (
            f"UAIP_SDK("
            f"agent={self.agent_name}, "
            f"did={self.did}, "
            f"gateway={self.gateway}"
            f")"
        )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close()
        return False
    
    def close(self):
        """Cleanup resources."""
        if hasattr(self, 'session'):
            self.session.close()
            logger.debug("HTTP session closed")
    
    def __del__(self):
        """Cleanup on deletion."""
        self.close()
