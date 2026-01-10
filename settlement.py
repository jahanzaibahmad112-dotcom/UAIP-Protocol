from decimal import Decimal, InvalidOperation, ROUND_DOWN
import uuid
import json
import time
import threading
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UAIPFinancialEngine:
    """
    3-Tiered Revenue Model with Security & Audit Controls:
    Tier A (<$10): $0.01 flat fee.
    Tier B ($10-$10k): 1.0% tax.
    Tier C (>$10k): $10 flat + 0.5% tax.
    
    Security Features:
    - Decimal precision for financial calculations (no float arithmetic)
    - Input validation and sanitization
    - Idempotency protection
    - Comprehensive audit trail
    - Thread-safe operations
    - Maximum transaction limits
    - Negative amount protection
    """
    
    # Constants
    MAX_AMOUNT = Decimal('1000000000')  # $1B max per transaction
    MIN_AMOUNT = Decimal('0.01')  # $0.01 minimum
    TIER_A_THRESHOLD = Decimal('10')
    TIER_B_THRESHOLD = Decimal('10000')
    
    # Supported blockchain networks
    SUPPORTED_CHAINS = {
        'BASE': {'name': 'Base', 'currency': 'USDC', 'min_confirmations': 12},
        'SOLANA': {'name': 'Solana', 'currency': 'USDC', 'min_confirmations': 32},
        'ETHEREUM': {'name': 'Ethereum', 'currency': 'USDC', 'min_confirmations': 12},
        'POLYGON': {'name': 'Polygon', 'currency': 'USDC', 'min_confirmations': 128}
    }
    
    def __init__(self, log_dir: str = ".", treasury_did: Optional[str] = None):
        """
        Initialize the Financial Engine.
        
        Args:
            log_dir: Directory for settlement logs
            treasury_did: Override default treasury DID (for testing)
        """
        self.hq_treasury = treasury_did or "did:uaip:protocol_hq_treasury"
        
        # Fee structure with high precision
        self.tiers = {
            "NANO_FLAT": Decimal('0.01'),      # Tier A: $0.01 flat
            "MID_RATE": Decimal('0.01'),       # Tier B: 1.0%
            "ENT_RATE": Decimal('0.005'),      # Tier C: 0.5%
            "ENT_FLAT": Decimal('10.0')        # Tier C: $10 base
        }
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Idempotency tracking (prevent duplicate settlements)
        self.processed_transactions = set()
        self.tx_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_transactions': 0,
            'total_volume': Decimal('0'),
            'total_fees_collected': Decimal('0'),
            'failed_transactions': 0
        }
        self.stats_lock = threading.Lock()
        
        # Setup settlement logging
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.settlement_log_path = self.log_dir / "uaip_settlements.jsonl"
        
        logger.info(f"Financial Engine initialized. Treasury: {self.hq_treasury}")
    
    def _validate_amount(self, amount: Any) -> Decimal:
        """
        Validate and convert amount to Decimal with security checks.
        
        Args:
            amount: Amount to validate (can be str, int, float, or Decimal)
            
        Returns:
            Validated Decimal amount
            
        Raises:
            ValueError: If amount is invalid
        """
        try:
            # Convert to Decimal (avoid float precision issues)
            if isinstance(amount, float):
                # Warn about float usage but accept it
                logger.warning(f"Float amount detected: {amount}. Use Decimal for precision.")
                amount_dec = Decimal(str(amount))
            elif isinstance(amount, (int, str)):
                amount_dec = Decimal(str(amount))
            elif isinstance(amount, Decimal):
                amount_dec = amount
            else:
                raise ValueError(f"Unsupported amount type: {type(amount)}")
            
            # Validate range
            if amount_dec < 0:
                raise ValueError("Amount cannot be negative")
            
            if amount_dec < self.MIN_AMOUNT:
                raise ValueError(f"Amount below minimum: {self.MIN_AMOUNT}")
            
            if amount_dec > self.MAX_AMOUNT:
                raise ValueError(f"Amount exceeds maximum: {self.MAX_AMOUNT}")
            
            # Check for reasonable decimal places (max 18 for USDC precision)
            if amount_dec.as_tuple().exponent < -18:
                raise ValueError("Too many decimal places (max 18)")
            
            return amount_dec
            
        except (InvalidOperation, ValueError) as e:
            logger.error(f"Amount validation failed: {e}")
            raise ValueError(f"Invalid amount: {e}")
    
    def _validate_did(self, did: str, field_name: str = "DID") -> str:
        """
        Validate DID format.
        
        Args:
            did: DID to validate
            field_name: Name of field for error messages
            
        Returns:
            Validated DID
            
        Raises:
            ValueError: If DID is invalid
        """
        if not did or not isinstance(did, str):
            raise ValueError(f"{field_name} is required and must be a string")
        
        did = did.strip()
        
        # Basic length check
        if len(did) < 10 or len(did) > 500:
            raise ValueError(f"{field_name} length must be between 10 and 500 characters")
        
        # DID should start with 'did:' per W3C spec
        if not did.startswith('did:'):
            logger.warning(f"{field_name} does not follow DID format: {did}")
        
        return did
    
    def _validate_chain(self, chain: str) -> str:
        """
        Validate blockchain network.
        
        Args:
            chain: Chain identifier
            
        Returns:
            Normalized chain name
            
        Raises:
            ValueError: If chain is not supported
        """
        if not chain or not isinstance(chain, str):
            raise ValueError("Chain is required and must be a string")
        
        chain_upper = chain.upper().strip()
        
        if chain_upper not in self.SUPPORTED_CHAINS:
            raise ValueError(
                f"Unsupported chain: {chain}. "
                f"Supported chains: {', '.join(self.SUPPORTED_CHAINS.keys())}"
            )
        
        return chain_upper
    
    def calculate_fee(self, amount: Decimal) -> Decimal:
        """
        Calculate transaction fee based on tiered structure.
        
        Args:
            amount: Transaction amount (must be validated Decimal)
            
        Returns:
            Fee amount as Decimal
        """
        # Tier A: Nano transactions (<= $10)
        if amount <= self.TIER_A_THRESHOLD:
            fee = self.tiers["NANO_FLAT"]
            logger.debug(f"Tier A fee applied: {fee}")
            return fee
        
        # Tier B: Mid-range ($10 - $10k)
        if amount <= self.TIER_B_THRESHOLD:
            fee = amount * self.tiers["MID_RATE"]
            logger.debug(f"Tier B fee applied: {fee} ({self.tiers['MID_RATE']*100}%)")
            return fee
        
        # Tier C: Enterprise (> $10k)
        fee = (amount * self.tiers["ENT_RATE"]) + self.tiers["ENT_FLAT"]
        logger.debug(f"Tier C fee applied: {fee} (${self.tiers['ENT_FLAT']} + {self.tiers['ENT_RATE']*100}%)")
        return fee
    
    def _check_idempotency(self, idempotency_key: Optional[str] = None) -> bool:
        """
        Check if transaction has already been processed.
        
        Args:
            idempotency_key: Optional key for duplicate detection
            
        Returns:
            True if transaction is new, False if duplicate
        """
        if not idempotency_key:
            return True  # No key provided, allow transaction
        
        with self.tx_lock:
            if idempotency_key in self.processed_transactions:
                logger.warning(f"Duplicate transaction detected: {idempotency_key}")
                return False
            
            self.processed_transactions.add(idempotency_key)
            
            # Limit set size to prevent memory issues (keep last 10,000)
            if len(self.processed_transactions) > 10000:
                # Remove oldest (note: set doesn't preserve order, this is approximate)
                self.processed_transactions.pop()
        
        return True
    
    def _log_settlement(self, settlement_record: Dict[str, Any]):
        """
        Write settlement to audit log in thread-safe manner.
        
        Args:
            settlement_record: Settlement details to log
        """
        try:
            with self.lock:
                with open(self.settlement_log_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(settlement_record, default=str) + '\n')
        except IOError as e:
            logger.error(f"Failed to write settlement log: {e}")
            # Don't fail the transaction just because logging failed
    
    def process_settlement(
        self,
        payer_did: str,
        amount_usd: Any,
        payee_did: str,
        chain: str,
        idempotency_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process a settlement transaction with full validation and audit trail.
        
        Args:
            payer_did: DID of the paying agent
            amount_usd: Amount in USD (will be converted to USDC)
            payee_did: DID of the receiving agent/service
            chain: Blockchain network for settlement
            idempotency_key: Optional key to prevent duplicate processing
            metadata: Optional additional transaction metadata
            
        Returns:
            Settlement result dictionary with tx_id, fee, payout, etc.
            
        Raises:
            ValueError: If inputs are invalid
            RuntimeError: If settlement processing fails
        """
        start_time = time.time()
        
        try:
            # 1. Validate all inputs
            validated_payer = self._validate_did(payer_did, "Payer DID")
            validated_payee = self._validate_did(payee_did, "Payee DID")
            validated_chain = self._validate_chain(chain)
            validated_amount = self._validate_amount(amount_usd)
            
            # 2. Check for duplicate transactions
            if not self._check_idempotency(idempotency_key):
                logger.warning(f"Duplicate settlement blocked: {idempotency_key}")
                raise ValueError("Duplicate transaction detected")
            
            # 3. Prevent self-payments (optional business rule)
            if validated_payer == validated_payee:
                raise ValueError("Payer and payee cannot be the same")
            
            # 4. Calculate fees with proper rounding
            fee = self.calculate_fee(validated_amount)
            fee = fee.quantize(Decimal('0.000001'), rounding=ROUND_DOWN)  # 6 decimal precision
            
            # 5. Calculate payout (ensure non-negative)
            payout = validated_amount - fee
            if payout < 0:
                raise ValueError(f"Fee ({fee}) exceeds amount ({validated_amount})")
            
            payout = payout.quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
            
            # 6. Generate transaction ID
            tx_id = f"uaip_tx_{uuid.uuid4().hex[:16]}"
            
            # 7. Prepare settlement record
            settlement_record = {
                'tx_id': tx_id,
                'timestamp': time.time(),
                'datetime': datetime.utcnow().isoformat(),
                'payer_did': validated_payer,
                'payee_did': validated_payee,
                'amount_usd': str(validated_amount),
                'fee_usd': str(fee),
                'payout_usd': str(payout),
                'chain': validated_chain,
                'chain_currency': self.SUPPORTED_CHAINS[validated_chain]['currency'],
                'treasury_did': self.hq_treasury,
                'idempotency_key': idempotency_key,
                'metadata': metadata or {},
                'processing_time_ms': None  # Will be filled later
            }
            
            # 8. Simulate blockchain settlement
            # In production, this would call actual blockchain APIs
            logger.info(
                f"💰 SETTLEMENT PROCESSED:\n"
                f"  TX ID: {tx_id}\n"
                f"  Amount: ${validated_amount} USD\n"
                f"  Fee: ${fee} USD ({(fee/validated_amount*100):.2f}%)\n"
                f"  Payout: ${payout} USD\n"
                f"  Payer: {validated_payer}\n"
                f"  Payee: {validated_payee}\n"
                f"  Chain: {validated_chain}\n"
                f"  Treasury: {self.hq_treasury}"
            )
            
            # 9. Update statistics
            with self.stats_lock:
                self.stats['total_transactions'] += 1
                self.stats['total_volume'] += validated_amount
                self.stats['total_fees_collected'] += fee
            
            # 10. Calculate processing time
            processing_time = (time.time() - start_time) * 1000  # Convert to ms
            settlement_record['processing_time_ms'] = round(processing_time, 2)
            
            # 11. Write to audit log
            self._log_settlement(settlement_record)
            
            # 12. Return settlement result
            return {
                'status': 'SUCCESS',
                'tx_id': tx_id,
                'amount': float(validated_amount),
                'fee': float(fee),
                'payout': float(payout),
                'chain': validated_chain,
                'currency': self.SUPPORTED_CHAINS[validated_chain]['currency'],
                'timestamp': settlement_record['timestamp'],
                'processing_time_ms': processing_time
            }
            
        except ValueError as e:
            # Business logic errors (invalid inputs)
            with self.stats_lock:
                self.stats['failed_transactions'] += 1
            
            logger.warning(f"Settlement validation failed: {e}")
            raise
            
        except Exception as e:
            # Unexpected errors
            with self.stats_lock:
                self.stats['failed_transactions'] += 1
            
            logger.error(f"Settlement processing error: {e}", exc_info=True)
            raise RuntimeError(f"Settlement failed: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics in a thread-safe manner.
        
        Returns:
            Dictionary of financial statistics
        """
        with self.stats_lock:
            return {
                'total_transactions': self.stats['total_transactions'],
                'total_volume_usd': float(self.stats['total_volume']),
                'total_fees_collected_usd': float(self.stats['total_fees_collected']),
                'failed_transactions': self.stats['failed_transactions'],
                'average_transaction_usd': (
                    float(self.stats['total_volume'] / self.stats['total_transactions'])
                    if self.stats['total_transactions'] > 0 else 0
                ),
                'average_fee_usd': (
                    float(self.stats['total_fees_collected'] / self.stats['total_transactions'])
                    if self.stats['total_transactions'] > 0 else 0
                )
            }
    
    def reset_statistics(self):
        """Reset statistics (for testing/admin purposes)."""
        with self.stats_lock:
            self.stats = {
                'total_transactions': 0,
                'total_volume': Decimal('0'),
                'total_fees_collected': Decimal('0'),
                'failed_transactions': 0
            }
        logger.info("Statistics reset")
    
    def calculate_projected_fee(self, amount: Any) -> Dict[str, Any]:
        """
        Calculate projected fee without processing transaction (for UI/estimates).
        
        Args:
            amount: Amount to calculate fee for
            
        Returns:
            Dictionary with fee breakdown
        """
        try:
            validated_amount = self._validate_amount(amount)
            fee = self.calculate_fee(validated_amount)
            fee = fee.quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
            payout = validated_amount - fee
            
            # Determine tier
            if validated_amount <= self.TIER_A_THRESHOLD:
                tier = "A (Nano)"
            elif validated_amount <= self.TIER_B_THRESHOLD:
                tier = "B (Mid-Range)"
            else:
                tier = "C (Enterprise)"
            
            return {
                'amount': float(validated_amount),
                'fee': float(fee),
                'payout': float(payout),
                'fee_percentage': float((fee / validated_amount * 100)),
                'tier': tier
            }
        except ValueError as e:
            logger.warning(f"Fee projection failed: {e}")
            raise


# Factory function for dependency injection
def get_financial_engine() -> UAIPFinancialEngine:
    """Get or create a singleton financial engine instance."""
    if not hasattr(get_financial_engine, '_instance'):
        get_financial_engine._instance = UAIPFinancialEngine()
    return get_financial_engine._instance
