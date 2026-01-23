from decimal import Decimal, InvalidOperation, ROUND_DOWN
import uuid
import json
import time
import threading
import logging
import re
import sqlite3
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from cryptography.fernet import Fernet
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)


class Web3Provider:
    """
    Placeholder for real Web3 integration.
    
    Production integration would use:
    - web3.py for Ethereum/Base/Polygon: pip install web3
    - solders + solana-py for Solana: pip install solana solders
    
    Example real implementation:
    ```python
    from web3 import Web3
    from solana.rpc.api import Client
    from spl.token.instructions import transfer_checked
    ```
    """
    
    def __init__(self, chain: str, rpc_url: Optional[str] = None):
        self.chain = chain
        self.rpc_url = rpc_url or self._get_default_rpc(chain)
        logger.info(f"🔗 Web3Provider initialized for {chain} (RPC: {self.rpc_url})")
    
    def _get_default_rpc(self, chain: str) -> str:
        """Get default RPC URL for chain."""
        return {
            'BASE': 'https://mainnet.base.org',
            'ETHEREUM': 'https://eth.llamarpc.com',
            'POLYGON': 'https://polygon-rpc.com',
            'SOLANA': 'https://api.mainnet-beta.solana.com'
        }.get(chain, '')
    
    def send_usdc_transaction(
        self, from_address: str, to_address: str, 
        amount_usdc: Decimal, decimals: int = 6
    ) -> Dict[str, Any]:
        """
        PLACEHOLDER: Send USDC on blockchain.
        
        Real implementation would:
        1. Build USDC transfer transaction
        2. Sign with private key from secure storage
        3. Broadcast to network
        4. Wait for confirmations
        
        For EVM chains (Base/Ethereum/Polygon):
        ```python
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        usdc = w3.eth.contract(address=USDC_ADDRESS, abi=ERC20_ABI)
        amount_wei = int(amount_usdc * (10 ** decimals))
        tx = usdc.functions.transfer(to_address, amount_wei).build_transaction({
            'from': from_address,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(from_address)
        })
        signed = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        ```
        
        For Solana:
        ```python
        client = Client(self.rpc_url)
        # Build SPL token transfer instruction
        # Sign and send transaction
        ```
        """
        tx_hash = f"0x{hashlib.sha256(f'{from_address}{to_address}{amount_usdc}{time.time()}'.encode()).hexdigest()}"
        
        logger.info(
            f"📡 [SIMULATED] Blockchain TX:\n"
            f"  Chain: {self.chain}\n"
            f"  From: {from_address}\n"
            f"  To: {to_address}\n"
            f"  Amount: {amount_usdc} USDC\n"
            f"  TX: {tx_hash}"
        )
        
        return {
            'success': True,
            'tx_hash': tx_hash,
            'chain': self.chain,
            'confirmations': 12,
            'status': 'confirmed'
        }


class PIIProtection:
    """
    Privacy protection for sensitive metadata.
    Uses Fernet symmetric encryption for PII fields.
    """
    
    PII_FIELDS = {
        'email', 'name', 'phone', 'address', 'ssn', 'tax_id',
        'user_name', 'full_name', 'ip_address', 'device_id',
        'customer_name', 'billing_address', 'shipping_address'
    }
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        if encryption_key is None:
            encryption_key = Fernet.generate_key()
            logger.warning("⚠️  New encryption key generated. Use secure key management in production.")
        
        self.cipher = Fernet(encryption_key)
    
    def _is_pii_field(self, field_name: str) -> bool:
        return any(pii in field_name.lower() for pii in self.PII_FIELDS)
    
    def encrypt_value(self, value: str) -> str:
        try:
            encrypted = self.cipher.encrypt(value.encode('utf-8'))
            return f"encrypted:{base64.b64encode(encrypted).decode('utf-8')}"
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return "[REDACTED]"
    
    def scrub_metadata(self, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Encrypt PII fields, preserve non-PII."""
        if not metadata or not isinstance(metadata, dict):
            return {}
        
        scrubbed = {}
        for key, value in metadata.items():
            if self._is_pii_field(key):
                if isinstance(value, str):
                    scrubbed[key] = self.encrypt_value(value)
                elif isinstance(value, dict):
                    scrubbed[key] = self.scrub_metadata(value)
                else:
                    scrubbed[key] = "[REDACTED]"
            else:
                scrubbed[key] = self.scrub_metadata(value) if isinstance(value, dict) else value
        
        return scrubbed


class UAIPFinancialEngine:
    """
    Production Financial Settlement Engine with:
    ✅ SQLite persistence (survives restarts)
    ✅ Web3 integration placeholders
    ✅ PII encryption
    ✅ String-based API responses (no float rounding)
    """
    
    MAX_AMOUNT = Decimal('1000000000')
    MIN_AMOUNT = Decimal('0.01')
    TIER_A_THRESHOLD = Decimal('10')
    TIER_B_THRESHOLD = Decimal('10000')
    FEE_PRECISION = Decimal('0.000001')
    
    SUPPORTED_CHAINS = {
        'BASE': {'name': 'Base', 'currency': 'USDC', 'decimals': 6},
        'SOLANA': {'name': 'Solana', 'currency': 'USDC', 'decimals': 6},
        'ETHEREUM': {'name': 'Ethereum', 'currency': 'USDC', 'decimals': 6},
        'POLYGON': {'name': 'Polygon', 'currency': 'USDC', 'decimals': 6}
    }
    
    MAX_DID_LENGTH = 500
    MIN_DID_LENGTH = 10
    MAX_METADATA_SIZE = 10000
    
    def __init__(
        self, log_dir: str = ".", treasury_did: Optional[str] = None,
        enable_self_payment: bool = False, db_path: Optional[str] = None,
        encryption_key: Optional[bytes] = None
    ):
        self.hq_treasury = treasury_did or "did:uaip:protocol_hq_treasury"
        self.enable_self_payment = enable_self_payment
        
        self.tiers = {
            "NANO_FLAT": Decimal('0.01'),
            "MID_RATE": Decimal('0.01'),
            "ENT_RATE": Decimal('0.005'),
            "ENT_FLAT": Decimal('10.0')
        }
        
        self.file_lock = threading.Lock()
        self.db_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        self.pii_protection = PIIProtection(encryption_key)
        
        self.log_dir = self._validate_log_dir(log_dir)
        self.db_path = db_path or str(self.log_dir / "uaip_settlements.db")
        self._init_database()
        
        self.stats = {
            'total_transactions': 0, 'total_volume': Decimal('0'),
            'total_fees_collected': Decimal('0'), 'failed_transactions': 0,
            'tier_a_count': 0, 'tier_b_count': 0, 'tier_c_count': 0
        }
        
        self.settlement_log_path = self.log_dir / "uaip_settlements.jsonl"
        self.web3_providers: Dict[str, Web3Provider] = {}
        
        logger.info(f"✅ Engine initialized: DB={self.db_path}, PII protection enabled")
    
    def _init_database(self):
        """Initialize SQLite with idempotency and settlement tables."""
        try:
            with self._get_db_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS processed_tx (
                        idempotency_key TEXT PRIMARY KEY,
                        tx_id TEXT NOT NULL,
                        processed_at REAL NOT NULL,
                        payer_did TEXT NOT NULL,
                        payee_did TEXT NOT NULL,
                        amount_usd TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_tx(processed_at)")
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS settlements (
                        tx_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        payer_did TEXT, payee_did TEXT,
                        amount_usd TEXT, fee_usd TEXT, payout_usd TEXT,
                        fee_tier TEXT, chain TEXT,
                        blockchain_tx_hash TEXT,
                        status TEXT DEFAULT 'completed',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                conn.commit()
                logger.info("✅ Database initialized")
        except sqlite3.Error as e:
            logger.error(f"❌ Database init failed: {e}")
            raise RuntimeError(f"DB initialization failed: {e}")
    
    @contextmanager
    def _get_db_connection(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
        finally:
            if conn:
                conn.close()
    
    def _validate_log_dir(self, log_dir: str) -> Path:
        try:
            abs_path = Path(log_dir).resolve()
            abs_path.mkdir(parents=True, exist_ok=True, mode=0o750)
            return abs_path
        except Exception as e:
            logger.error(f"Log dir setup failed: {e}")
            return Path.cwd()
    
    def _validate_amount(self, amount: Any) -> Decimal:
        try:
            if isinstance(amount, float):
                logger.warning(f"Float detected: {amount}. Use Decimal/string for precision.")
                amount_dec = Decimal(str(amount))
            elif isinstance(amount, (int, str)):
                amount_dec = Decimal(str(amount))
            elif isinstance(amount, Decimal):
                amount_dec = amount
            else:
                raise ValueError(f"Unsupported type: {type(amount).__name__}")
            
            if not amount_dec.is_finite():
                raise ValueError("Amount must be finite")
            if amount_dec < 0:
                raise ValueError("Amount cannot be negative")
            if amount_dec < self.MIN_AMOUNT and amount_dec != 0:
                raise ValueError(f"Below minimum: ${self.MIN_AMOUNT}")
            if amount_dec > self.MAX_AMOUNT:
                raise ValueError(f"Exceeds maximum: ${self.MAX_AMOUNT}")
            
            return amount_dec
        except (InvalidOperation, ValueError) as e:
            raise ValueError(f"Invalid amount: {e}")
    
    def _validate_did(self, did: str, field: str = "DID") -> str:
        if not did or not isinstance(did, str):
            raise ValueError(f"{field} required")
        did = did.strip()
        if len(did) < self.MIN_DID_LENGTH or len(did) > self.MAX_DID_LENGTH:
            raise ValueError(f"{field} length invalid")
        if not re.match(r'^[\w:.\-]+$', did):
            raise ValueError(f"{field} has invalid characters")
        return did
    
    def _validate_chain(self, chain: str) -> str:
        if not chain:
            raise ValueError("Chain required")
        chain = chain.upper().strip()
        if chain not in self.SUPPORTED_CHAINS:
            raise ValueError(f"Unsupported chain: {chain}")
        return chain
    
    def _validate_metadata(self, metadata: Optional[Dict]) -> Optional[Dict]:
        if metadata is None:
            return None
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be dict")
        if len(json.dumps(metadata)) > self.MAX_METADATA_SIZE:
            raise ValueError("Metadata too large")
        return metadata
    
    def calculate_fee(self, amount: Decimal) -> Decimal:
        if amount <= self.TIER_A_THRESHOLD:
            return self.tiers["NANO_FLAT"]
        if amount <= self.TIER_B_THRESHOLD:
            return amount * self.tiers["MID_RATE"]
        return (amount * self.tiers["ENT_RATE"]) + self.tiers["ENT_FLAT"]
    
    def _check_idempotency(self, key: Optional[str]) -> bool:
        """Check if transaction already processed (DB-backed)."""
        if not key:
            return True
        
        try:
            with self.db_lock, self._get_db_connection() as conn:
                cursor = conn.execute(
                    "SELECT tx_id, processed_at FROM processed_tx WHERE idempotency_key = ?",
                    (key,)
                )
                result = cursor.fetchone()
                
                if result:
                    logger.warning(f"🔄 Duplicate: {key} (TX: {result[0]})")
                    return False
                return True
        except sqlite3.Error as e:
            logger.error(f"DB error in idempotency: {e}")
            return False  # Fail-safe: reject on DB error
    
    def _record_idempotency(self, key: str, tx_id: str, payer: str, payee: str, amount: Decimal):
        """Persist idempotency record to survive restarts."""
        try:
            with self.db_lock, self._get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO processed_tx VALUES (?, ?, ?, ?, ?, ?)",
                    (key, tx_id, time.time(), payer, payee, str(amount))
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to record idempotency: {e}")
    
    def _get_web3_provider(self, chain: str) -> Web3Provider:
        if chain not in self.web3_providers:
            self.web3_providers[chain] = Web3Provider(chain)
        return self.web3_providers[chain]
    
    def _log_settlement(self, record: Dict[str, Any]):
        """Log settlement with PII scrubbing."""
        try:
            if 'metadata' in record:
                record['metadata'] = self.pii_protection.scrub_metadata(record['metadata'])
            
            with self.file_lock:
                with open(self.settlement_log_path, 'a', encoding='utf-8') as f:
                    json.dump(record, f, default=str)
                    f.write('\n')
                    f.flush()
        except Exception as e:
            logger.error(f"❌ Log failed: {e}")
    
    def process_settlement(
        self, payer_did: str, amount_usd: Any, payee_did: str,
        chain: str, idempotency_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process settlement with full validation, DB persistence, and blockchain integration.
        
        Returns string-based amounts to prevent float rounding in frontend.
        """
        start = time.time()
        
        try:
            # Validation
            payer = self._validate_did(payer_did, "Payer")
            payee = self._validate_did(payee_did, "Payee")
            validated_chain = self._validate_chain(chain)
            amount = self._validate_amount(amount_usd)
            meta = self._validate_metadata(metadata)
            
            # Idempotency check (DB-backed)
            if not self._check_idempotency(idempotency_key):
                raise ValueError(f"Duplicate transaction: {idempotency_key}")
            
            # Business rules
            if not self.enable_self_payment and payer == payee:
                raise ValueError("Self-payment not allowed")
            
            # Fee calculation
            fee = self.calculate_fee(amount).quantize(self.FEE_PRECISION, rounding=ROUND_DOWN)
            payout = (amount - fee).quantize(self.FEE_PRECISION, rounding=ROUND_DOWN)
            
            if payout < 0:
                raise ValueError("Fee exceeds amount")
            
            # Generate TX ID
            tx_id = f"uaip_tx_{uuid.uuid4().hex[:16]}"
            
            # Determine tier
            if amount <= self.TIER_A_THRESHOLD:
                tier = "A"
            elif amount <= self.TIER_B_THRESHOLD:
                tier = "B"
            else:
                tier = "C"
            
            # Blockchain settlement (placeholder)
            web3 = self._get_web3_provider(validated_chain)
            blockchain_result = web3.send_usdc_transaction(
                from_address="treasury_wallet",  # In production: resolve from treasury DID
                to_address="payee_wallet",  # In production: resolve from payee DID
                amount_usdc=payout,
                decimals=self.SUPPORTED_CHAINS[validated_chain]['decimals']
            )
            
            # Settlement record
            record = {
                'tx_id': tx_id,
                'timestamp': time.time(),
                'datetime_utc': datetime.utcnow().isoformat() + 'Z',
                'payer_did': payer,
                'payee_did': payee,
                'amount_usd': str(amount),  # STRING for precision
                'fee_usd': str(fee),
                'payout_usd': str(payout),
                'fee_tier': tier,
                'chain': validated_chain,
                'chain_currency': self.SUPPORTED_CHAINS[validated_chain]['currency'],
                'treasury_did': self.hq_treasury,
                'blockchain_tx_hash': blockchain_result.get('tx_hash'),
                'blockchain_status': blockchain_result.get('status'),
                'idempotency_key': idempotency_key,
                'metadata': meta or {},
                'version': '2.0.0'
            }
            
            logger.info(
                f"💰 SETTLEMENT:\n"
                f"  TX: {tx_id}\n"
                f"  Amount: ${amount} | Fee: ${fee} | Payout: ${payout}\n"
                f"  {payer} → {payee}\n"
                f"  Chain: {validated_chain} | Blockchain TX: {blockchain_result.get('tx_hash')}"
            )
            
            # Update stats
            with self.stats_lock:
                self.stats['total_transactions'] += 1
                self.stats['total_volume'] += amount
                self.stats['total_fees_collected'] += fee
                self.stats[f'tier_{tier.lower()}_count'] += 1
            
            # Persist idempotency
            if idempotency_key:
                self._record_idempotency(idempotency_key, tx_id, payer, payee, amount)
            
            # Store in settlements table
            try:
                with self.db_lock, self._get_db_connection() as conn:
                    conn.execute(
                        """INSERT INTO settlements 
                           (tx_id, timestamp, payer_did, payee_did, amount_usd, fee_usd, 
                            payout_usd, fee_tier, chain, blockchain_tx_hash, status)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (tx_id, time.time(), payer, payee, str(amount), str(fee),
                         str(payout), tier, validated_chain, blockchain_result.get('tx_hash'), 'completed')
                    )
                    conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Failed to store settlement: {e}")
            
            # Log to JSONL (with PII scrubbing)
            processing_time = (time.time() - start) * 1000
            record['processing_time_ms'] = round(processing_time, 2)
            self._log_settlement(record)
            
            # Return with STRING amounts (critical for frontend precision)
            return {
                'status': 'SUCCESS',
                'tx_id': tx_id,
                'amount': str(amount),  # STRING
                'fee': str(fee),  # STRING
                'payout': str(payout),  # STRING
                'fee_percentage': str((fee / amount * 100) if amount > 0 else 0),  # STRING
                'tier': tier,
                'chain': validated_chain,
                'currency': self.SUPPORTED_CHAINS[validated_chain]['currency'],
                'blockchain_tx_hash': blockchain_result.get('tx_hash'),
                'timestamp': record['timestamp'],
                'processing_time_ms': processing_time
            }
            
        except ValueError as e:
            with self.stats_lock:
                self.stats['failed_transactions'] += 1
            logger.warning(f"⚠️  Validation failed: {e}")
            raise
        except Exception as e:
            with self.stats_lock:
                self.stats['failed_transactions'] += 1
            logger.error(f"❌ Settlement error: {e}", exc_info=True)
            raise RuntimeError(f"Settlement failed: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        with self.stats_lock:
            avg_tx = Decimal('0')
            avg_fee = Decimal('0')
            avg_fee_pct = Decimal('0')
            
            if self.stats['total_transactions'] > 0:
                avg_tx = self.stats['total_volume'] / self.stats['total_transactions']
                avg_fee = self.stats['total_fees_collected'] / self.stats['total_transactions']
                if self.stats['total_volume'] > 0:
                    avg_fee_pct = self.stats['total_fees_collected'] / self.stats['total_volume'] * 100
            
            return {
                'total_transactions': self.stats['total_transactions'],
                'successful': self.stats['total_transactions'] - self.stats['failed_transactions'],
                'failed': self.stats['failed_transactions'],
                'total_volume_usd': str(self.stats['total_volume']),  # STRING
                'total_fees_usd': str(self.stats['total_fees_collected']),  # STRING
                'avg_transaction_usd': str(avg_tx),  # STRING
                'avg_fee_usd': str(avg_fee),  # STRING
                'avg_fee_percentage': str(avg_fee_pct),  # STRING
                'tiers': {
                    'A': self.stats['tier_a_count'],
                    'B': self.stats['tier_b_count'],
                    'C': self.stats['tier_c_count']
                }
            }
    
    def calculate_projected_fee(self, amount: Any) -> Dict[str, Any]:
        """Calculate fee without processing (for UI)."""
        amount_dec = self._validate_amount(amount)
        fee = self.calculate_fee(amount_dec).quantize(self.FEE_PRECISION, rounding=ROUND_DOWN)
        payout = amount_dec - fee
        
        if amount_dec <= self.TIER_A_THRESHOLD:
            tier, name = "A", "Nano"
        elif amount_dec <= self.TIER_B_THRESHOLD:
            tier, name = "B", "Mid-Range"
        else:
            tier, name = "C", "Enterprise"
        
        return {
            'amount': str(amount_dec),  # STRING
            'fee': str(fee),  # STRING
            'payout': str(payout),  # STRING
            'fee_percentage': str((fee / amount_dec * 100) if amount_dec > 0 else 0),  # STRING
            'tier': tier,
            'tier_name': name
        }
    
    def health_check(self) -> Dict[str, Any]:
        try:
            test_file = self.log_dir / ".health"
            test_file.write_text("ok")
            test_file.unlink()
            log_ok = True
        except:
            log_ok = False
        
        try:
            with self._get_db_connection() as conn:
                conn.execute("SELECT 1")
            db_ok = True
        except:
            db_ok = False
        
        return {
            'status': 'healthy' if (log_ok and db_ok) else 'degraded',
            'log_writable': log_ok,
            'database_ok': db_ok,
            'db_path': self.db_path,
            'treasury': self.hq_treasury,
            'chains': list(self.SUPPORTED_CHAINS.keys()),
            'stats': self.get_statistics()
        }


def get_financial_engine(
    log_dir: str = ".", treasury_did: Optional[str] = None
) -> UAIPFinancialEngine:
    """Singleton factory for financial engine."""
    if not hasattr(get_financial_engine, '_instance'):
        get_financial_engine._instance = UAIPFinancialEngine(
            log_dir=log_dir, treasury_did=treasury_did
        )
    return get_financial_engine._instance