from fastapi import FastAPI, HTTPException, Header, Request, Path
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, field_validator, Field
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from contextlib import contextmanager
import uuid, time, json, html, os, sqlite3, threading, secrets, logging, hashlib
import nacl.signing, nacl.encoding
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import re
import queue

# --- INTERNAL SYSTEM IMPORTS ---
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('uaip_gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UAIP Master Gateway",
    version="1.0.0",
    docs_url=None,
    redoc_url=None
)

# --- CONFIGURATION ---
ADMIN_KEY = os.getenv("ADMIN_KEY")
if not ADMIN_KEY or len(ADMIN_KEY) < 32:
    logger.critical("ADMIN_KEY must be set with minimum 32 characters!")
    raise RuntimeError("Insecure ADMIN_KEY configuration")

# SECURITY FIX: Hash admin key for secure comparison
ADMIN_KEY_HASH = hashlib.sha256(ADMIN_KEY.encode()).hexdigest()

DB_PATH = os.getenv("DB_PATH", "uaip_vault.db")
UAIP_VERSION = "1.0.0"
SETTLEMENT_PROVIDER = os.getenv("SETTLEMENT_PROVIDER", "provider_01")

# SECURITY FIX: Strict trusted proxies validation
TRUSTED_PROXIES_STR = os.getenv("TRUSTED_PROXIES", "")
TRUSTED_PROXIES = set()
if TRUSTED_PROXIES_STR:
    for proxy_ip in TRUSTED_PROXIES_STR.split(","):
        proxy_ip = proxy_ip.strip()
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', proxy_ip):
            TRUSTED_PROXIES.add(proxy_ip)
        else:
            logger.warning(f"Invalid proxy IP format ignored: {proxy_ip}")

# Security Constants
MAX_AMOUNT = Decimal("1000000000")
MIN_AMOUNT = Decimal("0.01")
MAX_TASK_LENGTH = 5000
MAX_INTENT_LENGTH = 2000
MAX_DID_LENGTH = 500
NONCE_EXPIRY_SECONDS = 120
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 100
LOCKOUT_DURATION = 300
MAX_FAILED_ATTEMPTS = 5
TIMESTAMP_TOLERANCE = 30
SESSION_EXPIRY = 3600  # 1 hour

SUPPORTED_CHAINS = {"BASE", "SOLANA", "ETHEREUM", "POLYGON"}

# Chain-specific decimal precision
CHAIN_DECIMALS = {
    "BASE": 18,
    "SOLANA": 9,
    "ETHEREUM": 18,
    "POLYGON": 18
}

# --- SECURITY MIDDLEWARE ---
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Key", "X-Session-Token"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,*.uaip.io").split(",")
)

# --- DATABASE CONNECTION POOL ---
class DBConnectionPool:
    """Thread-safe database connection pool"""
    def __init__(self, db_path: str, pool_size: int = 5):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=pool_size)

        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA foreign_keys=ON;')
            conn.execute('PRAGMA busy_timeout=5000;')
            self.pool.put(conn)

        logger.info(f"Database connection pool initialized with {pool_size} connections")

    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Database error: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Database operation failed")
        except Exception as e:
            conn.rollback()
            logger.error(f"Unexpected error in database session: {e}", exc_info=True)
            raise
        finally:
            self.pool.put(conn)

db_pool = None

@contextmanager
def db_session():
    """Database session context manager"""
    if db_pool is None:
        raise RuntimeError("Database pool not initialized")
    with db_pool.get_connection() as conn:
        yield conn

# --- DATA MODELS WITH VALIDATION ---
class UAIPPacket(BaseModel):
    sender_id: str = Field(..., max_length=MAX_DID_LENGTH)
    task: str = Field(..., max_length=MAX_TASK_LENGTH)
    amount: str = Field(..., pattern=r'^\d+(\.\d{1,18})?$')
    chain: str = Field(..., max_length=50)
    intent: str = Field(..., max_length=MAX_INTENT_LENGTH)
    data: dict
    signature: str = Field(..., pattern=r'^[0-9a-fA-F]+$')
    public_key: str = Field(..., pattern=r'^[0-9a-fA-F]+$')
    nonce: str = Field(..., pattern=r'^[0-9a-f\-]+$')
    timestamp: float
    zk_proof: dict

    @field_validator('chain')
    @classmethod
    def validate_chain(cls, v):
        if v.upper() not in SUPPORTED_CHAINS:
            raise ValueError(f'Chain must be one of {SUPPORTED_CHAINS}')
        return v.upper()

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        now = time.time()
        if abs(v - now) > TIMESTAMP_TOLERANCE:
            raise ValueError(f'Timestamp outside acceptable range (±{TIMESTAMP_TOLERANCE}s)')
        return v

    @field_validator('amount')
    @classmethod
    def validate_amount(cls, v):
        try:
            amount = Decimal(v)
            if amount < MIN_AMOUNT:
                raise ValueError(f'Amount must be at least {MIN_AMOUNT}')
            if amount > MAX_AMOUNT:
                raise ValueError(f'Amount exceeds maximum {MAX_AMOUNT}')
            return v
        except (InvalidOperation, ValueError) as e:
            raise ValueError(f'Invalid amount format: {e}')

    @field_validator('data')
    @classmethod
    def validate_data(cls, v):
        if len(json.dumps(v)) > 10000:
            raise ValueError('Data payload too large')
        return v

    @field_validator('zk_proof')
    @classmethod
    def validate_zk_proof(cls, v):
        if len(json.dumps(v)) > 5000:
            raise ValueError('ZK proof payload too large')
        return v

class RegistrationRequest(BaseModel):
    registration_data: dict
    signature: str = Field(..., pattern=r'^[0-9a-fA-F]+$')
    public_key: str = Field(..., pattern=r'^[0-9a-fA-F]+$')

    @field_validator('registration_data')
    @classmethod
    def validate_registration_data(cls, v):
        if len(json.dumps(v)) > 10000:
            raise ValueError('Registration data too large')
        return v

# --- DATABASE INITIALIZATION ---
def init_db():
    """Initialize database schema with proper constraints"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()

            c.execute('''CREATE TABLE IF NOT EXISTS inventory (
                did TEXT PRIMARY KEY CHECK(length(did) <= 500 AND did != ''),
                pk TEXT NOT NULL CHECK(length(pk) <= 1000 AND pk != ''),
                zk_commitment TEXT NOT NULL CHECK(zk_commitment != ''),
                created_at REAL NOT NULL DEFAULT (julianday('now')),
                updated_at REAL NOT NULL DEFAULT (julianday('now'))
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_inventory_pk ON inventory(pk)')

            c.execute('''CREATE TABLE IF NOT EXISTS nonces (
                id TEXT PRIMARY KEY CHECK(length(id) <= 100 AND id != ''),
                ts REAL NOT NULL,
                sender_id TEXT NOT NULL
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_nonces_ts ON nonces(ts)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_nonces_sender ON nonces(sender_id)')

            c.execute('''CREATE TABLE IF NOT EXISTS pending (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK(status IN ('WAITING', 'APPROVED', 'REJECTED')),
                request_json TEXT NOT NULL,
                version TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (julianday('now')),
                approved_by TEXT,
                approved_at REAL
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_pending_status ON pending(status)')

            c.execute('''CREATE TABLE IF NOT EXISTS lockouts (
                ip TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until REAL,
                last_attempt REAL
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS action_logs (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                task TEXT NOT NULL,
                amount TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'PENDING', 'BLOCKED', 'HUMAN_APPROVED')),
                law TEXT,
                ts REAL NOT NULL,
                chain TEXT,
                intent TEXT,
                audit_id TEXT
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_logs_ts ON action_logs(ts DESC)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_logs_sender ON action_logs(sender)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_logs_decision ON action_logs(decision)')

            c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
                did TEXT PRIMARY KEY,
                reason TEXT,
                ts REAL NOT NULL,
                blocked_by TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
                identifier TEXT NOT NULL,
                window_start REAL NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (identifier, window_start)
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)')

            # SECURITY FIX: Admin session tracking
            c.execute('''CREATE TABLE IF NOT EXISTS admin_sessions (
                session_token TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                ip_address TEXT NOT NULL
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)')

            conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.critical(f"Failed to initialize database: {e}")
        raise

init_db()
db_pool = DBConnectionPool(DB_PATH, pool_size=5)

# --- SECURITY UTILITIES ---
def get_client_ip(request: Request) -> str:
    """SECURITY FIX: Get client IP with strict proxy validation"""
    if request.client and TRUSTED_PROXIES and request.client.host in TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', client_ip):
                return client_ip
            else:
                logger.warning(f"Invalid IP format in X-Forwarded-For: {client_ip}")
    
    return request.client.host if request.client else "127.0.0.1"

def check_rate_limit(identifier: str, max_requests: int = RATE_LIMIT_MAX_REQUESTS) -> bool:
    """SECURITY FIX: Fail-closed rate limiting"""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    try:
        with db_session() as conn:
            conn.execute('DELETE FROM rate_limits WHERE window_start < ?', (window_start,))

            result = conn.execute(
                'SELECT SUM(request_count) as total FROM rate_limits WHERE identifier=? AND window_start > ?',
                (identifier, window_start)
            ).fetchone()

            count = result['total'] if result and result['total'] else 0

            if count >= max_requests:
                logger.warning(f"Rate limit exceeded for {identifier}: {count}/{max_requests}")
                return False

            conn.execute(
                'INSERT OR REPLACE INTO rate_limits (identifier, window_start, request_count) VALUES (?, ?, ?)',
                (identifier, int(now), count + 1)
            )

            return True
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}", exc_info=True)
        # SECURITY FIX: Fail closed - block on error
        return False

def check_lockout(ip: str) -> bool:
    """SECURITY FIX: Fail-closed lockout checking"""
    try:
        with db_session() as conn:
            lockout = conn.execute(
                'SELECT lockout_until FROM lockouts WHERE ip=?',
                (ip,)
            ).fetchone()

            if lockout and lockout['lockout_until']:
                if time.time() < lockout['lockout_until']:
                    return True
                else:
                    conn.execute('DELETE FROM lockouts WHERE ip=?', (ip,))

            return False
    except Exception as e:
        logger.error(f"Lockout check failed: {e}", exc_info=True)
        # SECURITY FIX: Fail closed - lock out on error
        return True

def record_failed_attempt(ip: str):
    """Record failed authentication attempt and apply lockout if needed"""
    try:
        with db_session() as conn:
            lockout = conn.execute(
                'SELECT attempts FROM lockouts WHERE ip=?',
                (ip,)
            ).fetchone()

            attempts = (lockout['attempts'] if lockout else 0) + 1

            if attempts >= MAX_FAILED_ATTEMPTS:
                lockout_until = time.time() + LOCKOUT_DURATION
                conn.execute(
                    'INSERT OR REPLACE INTO lockouts (ip, attempts, lockout_until, last_attempt) VALUES (?, ?, ?, ?)',
                    (ip, attempts, lockout_until, time.time())
                )
                logger.warning(f"IP {ip} locked out after {attempts} failed attempts")
            else:
                conn.execute(
                    'INSERT OR REPLACE INTO lockouts (ip, attempts, last_attempt) VALUES (?, ?, ?)',
                    (ip, attempts, time.time())
                )
    except Exception as e:
        logger.error(f"Failed to record attempt: {e}", exc_info=True)

def sanitize_did(did: str) -> str:
    """SECURITY FIX: Sanitize DID with strict validation"""
    did = html.escape(did.strip())
    if not re.match(r'^[a-zA-Z0-9:_\-]+$', did):
        raise ValueError("Invalid DID format")
    return did[:MAX_DID_LENGTH]

def normalize_amount(amount: Decimal, chain: str) -> Decimal:
    """Normalize amount to chain-specific decimal precision"""
    decimals = CHAIN_DECIMALS.get(chain, 18)
    quantize_str = '1.' + '0' * decimals
    return amount.quantize(Decimal(quantize_str), rounding=ROUND_DOWN)

def verify_admin_key(provided_key: str) -> bool:
    """SECURITY FIX: Constant-time admin key verification"""
    if not provided_key:
        return False
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return secrets.compare_digest(provided_hash, ADMIN_KEY_HASH)

def create_admin_session(ip_address: str) -> str:
    """SECURITY FIX: Create secure admin session"""
    session_token = secrets.token_urlsafe(32)
    created_at = time.time()
    expires_at = created_at + SESSION_EXPIRY

    try:
        with db_session() as conn:
            conn.execute(
                'INSERT INTO admin_sessions (session_token, created_at, expires_at, ip_address) VALUES (?, ?, ?, ?)',
                (session_token, created_at, expires_at, ip_address)
            )
        return session_token
    except Exception as e:
        logger.error(f"Failed to create admin session: {e}")
        raise

def validate_admin_session(session_token: str, ip_address: str) -> bool:
    """SECURITY FIX: Validate admin session with IP binding"""
    if not session_token:
        return False
    
    try:
        with db_session() as conn:
            session = conn.execute(
                'SELECT expires_at, ip_address FROM admin_sessions WHERE session_token=?',
                (session_token,)
            ).fetchone()

            if not session:
                return False

            if time.time() > session['expires_at']:
                conn.execute('DELETE FROM admin_sessions WHERE session_token=?', (session_token,))
                return False

            if session['ip_address'] != ip_address:
                logger.warning(f"Session hijacking attempt: token from {session['ip_address']} used from {ip_address}")
                conn.execute('DELETE FROM admin_sessions WHERE session_token=?', (session_token,))
                return False

            return True
    except Exception as e:
        logger.error(f"Session validation failed: {e}")
        return False

def get_login_page() -> str:
    """SECURITY FIX: Secure login page"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AgentGuard Admin Login</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    background: linear-gradient(135deg, #0d1117 0%, #1a1f2e 100%);
                    color: #e6edf3;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }}
                .login-container {{
                    background: rgba(13, 17, 23, 0.8);
                    padding: 40px;
                    border-radius: 12px;
                    border: 1px solid rgba(88, 166, 255, 0.3);
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                    width: 100%;
                    max-width: 400px;
                }}
                h1 {{
                    color: #58a6ff;
                    margin-bottom: 30px;
                    text-align: center;
                    font-size: 1.8em;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #8b949e;
                }}
                input {{
                    width: 100%;
                    padding: 12px;
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(88, 166, 255, 0.2);
                    border-radius: 6px;
                    color: #e6edf3;
                    font-size: 1em;
                }}
                input:focus {{
                    outline: none;
                    border-color: #58a6ff;
                    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
                }}
                button {{
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-weight: 600;
                    font-size: 1em;
                    cursor: pointer;
                    transition: all 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(35, 134, 54, 0.4);
                }}
                button:disabled {{
                    opacity: 0.5;
                    cursor: not-allowed;
                }}
                .error {{
                    background: rgba(248, 81, 73, 0.1);
                    border: 1px solid rgba(248, 81, 73, 0.3);
                    color: #f85149;
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    display: none;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>🛡️ AgentGuard</h1>
                <div id="error" class="error"></div>
                <form id="loginForm">
                    <div class="form-group">
                        <label for="adminKey">Admin Key</label>
                        <input type="password" id="adminKey" required autocomplete="off">
                    </div>
                    <button type="submit" id="loginBtn">Login</button>
                </form>
            </div>

            <script>
                const form = document.getElementById('loginForm');
                const errorDiv = document.getElementById('error');
                const loginBtn = document.getElementById('loginBtn');

                form.addEventListener('submit', async (e) => {{
                    e.preventDefault();
                    
                    const adminKey = document.getElementById('adminKey').value;
                    errorDiv.style.display = 'none';
                    loginBtn.disabled = true;
                    loginBtn.textContent = 'Authenticating...';

                    try {{
                        const res = await fetch('/v1/admin/login', {{
                            method: 'POST',
                            headers: {{
                                'X-Admin-Key': adminKey
                            }}
                        }});

                        if (!res.ok) {{
                            throw new Error('Invalid credentials');
                        }}

                        const data = await res.json();
                        localStorage.setItem('admin_session', data.session_token);
                        window.location.reload();
                    }} catch (err) {{
                        errorDiv.textContent = '❌ ' + err.message;
                        errorDiv.style.display = 'block';
                        loginBtn.disabled = false;
                        loginBtn.textContent = 'Login';
                        document.getElementById('adminKey').value = '';
                    }}
                }});
            </script>
        </body>
    </html>
    """

# --- MAINTENANCE TASKS ---
def cleanup_task():
    """Background cleanup of expired database entries"""
    while True:
        try:
            with db_session() as conn:
                now = time.time()

                deleted_nonces = conn.execute(
                    'DELETE FROM nonces WHERE ts < ?',
                    (now - NONCE_EXPIRY_SECONDS,)
                ).rowcount

                deleted_logs = conn.execute(
                    'DELETE FROM action_logs WHERE ts < ?',
                    (now - 2592000,)
                ).rowcount

                deleted_rates = conn.execute(
                    'DELETE FROM rate_limits WHERE window_start < ?',
                    (now - RATE_LIMIT_WINDOW,)
                ).rowcount

                deleted_lockouts = conn.execute(
                    'DELETE FROM lockouts WHERE lockout_until < ? AND lockout_until IS NOT NULL',
                    (now,)
                ).rowcount

                deleted_sessions = conn.execute(
                    'DELETE FROM admin_sessions WHERE expires_at < ?',
                    (now,)
                ).rowcount

                if any([deleted_nonces, deleted_logs, deleted_rates, deleted_lockouts, deleted_sessions]):
                    logger.debug(
                        f"Cleanup: nonces={deleted_nonces}, logs={deleted_logs}, "
                        f"rates={deleted_rates}, lockouts={deleted_lockouts}, sessions={deleted_sessions}"
                    )
        except Exception as e:
            logger.error(f"Cleanup task error: {e}", exc_info=True)

        time.sleep(60)

cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
cleanup_thread.start()

# --- ENDPOINTS ---
@app.post("/v1/admin/login")
async def admin_login(
    request: Request,
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")
):
    """SECURITY FIX: Secure admin login endpoint"""
    client_ip = get_client_ip(request)
    
    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts")
    
    if not x_admin_key or not verify_admin_key(x_admin_key):
        record_failed_attempt(client_ip)
        logger.warning(f"Failed admin login from {client_ip}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    session_token = create_admin_session(client_ip)
    
    logger.info(f"Admin login successful from {client_ip}")
    return {
        "status": "authenticated",
        "session_token": session_token,
        "expires_in": SESSION_EXPIRY
    }

@app.post("/v1/admin/logout")
async def admin_logout(
    request: Request,
    x_session_token: Optional[str] = Header(None, alias="X-Session-Token")
):
    """SECURITY FIX: Admin logout endpoint"""
    if x_session_token:
        try:
            with db_session() as conn:
                conn.execute('DELETE FROM admin_sessions WHERE session_token=?', (x_session_token,))
        except Exception as e:
            logger.error(f"Logout error: {e}")
    
    return {"status": "logged_out"}

@app.post("/v1/register")
async def register(request: Request, req: RegistrationRequest):
    """Register a new agent with cryptographic identity verification"""
    client_ip = get_client_ip(request)

    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    if not check_rate_limit(f"register:{client_ip}", max_requests=10):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data = req.registration_data
        sig = req.signature
        pk = req.public_key

        if not data.get("agent_id") or not data.get("zk_commitment"):
            raise HTTPException(status_code=400, detail="Missing required fields: agent_id, zk_commitment")

        agent_id = sanitize_did(data["agent_id"])

        try:
            vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
            msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk.verify(msg, bytes.fromhex(sig))
        except Exception as e:
            logger.warning(f"Signature verification failed for {agent_id} from {client_ip}: {e}")
            record_failed_attempt(client_ip)
            raise HTTPException(status_code=401, detail="Invalid signature")

        try:
            commitment_val = int(str(data["zk_commitment"]))
            if commitment_val < 0:
                raise ValueError("Negative commitment")
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid zk_commitment format: {e}")

        with db_session() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO inventory (did, pk, zk_commitment, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
                (agent_id, pk, str(data["zk_commitment"]), time.time(), time.time())
            )

        logger.info(f"Agent registered: {agent_id} from {client_ip}")
        return {"status": "REGISTERED", "agent_id": agent_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/v1/execute")
async def execute(request: Request, req: UAIPPacket):
    """Execute a governed agent transaction with full security checks"""
    client_ip = get_client_ip(request)
    now = time.time()

    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts")

    if not check_rate_limit(f"execute:{req.sender_id}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        amount_dec = Decimal(req.amount)
        auditor = ComplianceAuditor()

        with db_session() as conn:
            blacklisted = conn.execute(
                'SELECT reason FROM blacklist WHERE did=?',
                (req.sender_id,)
            ).fetchone()

            if blacklisted:
                logger.warning(f"Blocked blacklisted agent: {req.sender_id}")
                raise HTTPException(
                    status_code=403,
                    detail=f"BLACKLISTED: {blacklisted['reason'] if blacklisted['reason'] else 'Policy violation'}"
                )

            existing_nonce = conn.execute(
                'SELECT 1 FROM nonces WHERE id=? LIMIT 1',
                (req.nonce,)
            ).fetchone()

            if existing_nonce:
                logger.warning(f"Replay attack detected: nonce={req.nonce}, sender={req.sender_id}, ip={client_ip}")
                record_failed_attempt(client_ip)
                raise HTTPException(status_code=403, detail="REPLAY_ATTACK_DETECTED")

            try:
                conn.execute(
                    'INSERT INTO nonces (id, ts, sender_id) VALUES (?, ?, ?)',
                    (req.nonce, now, req.sender_id)
                )
            except sqlite3.IntegrityError:
                logger.error(f"Race condition in nonce insertion: {req.nonce}")
                raise HTTPException(status_code=403, detail="REPLAY_ATTACK_DETECTED")

            try:
                vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
                msg = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                vk.verify(msg, bytes.fromhex(req.signature))

                agent = conn.execute(
                    'SELECT zk_commitment FROM inventory WHERE did=? AND pk=?',
                    (req.sender_id, req.public_key)
                ).fetchone()

                if not agent:
                    raise Exception("Agent not registered or public key mismatch")

                try:
                    commitment = int(agent['zk_commitment'])
                    if commitment < 0:
                        raise ValueError("Invalid commitment value")
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid ZK commitment format for {req.sender_id}: {e}")
                    raise Exception("Agent data corrupted - invalid ZK commitment")

                if not ZK_Privacy.verify_proof(req.zk_proof, commitment):
                    raise Exception("ZK proof verification failed")

            except Exception as e:
                logger.warning(f"Identity verification failed for {req.sender_id} from {client_ip}: {e}")
                record_failed_attempt(client_ip)
                raise HTTPException(status_code=401, detail="IDENTITY_VERIFICATION_FAILED")

            audit_log = {
                "sender": req.sender_id,
                "task": req.task,
                "amount": str(amount_dec),
                "chain": req.chain,
                "intent": req.intent,
                "timestamp": now
            }

            audit_status, audit_report = auditor.run_active_audit(audit_log)

            if audit_status == "TERMINATE":
                logger.warning(f"Transaction blocked by compliance: {req.sender_id}")
                conn.execute(
                    'INSERT OR REPLACE INTO blacklist (did, reason, ts, blocked_by) VALUES (?, ?, ?, ?)',
                    (req.sender_id, audit_report.get('verification_reasoning', 'Policy violation'), now, 'AUTO')
                )
                raise HTTPException(
                    status_code=451,
                    detail={"error": "COMPLIANCE_VIOLATION", "audit": audit_report}
                )

            requires_approval = (
                amount_dec >= Decimal("1000") or
                audit_status == "PENDING_ENFORCED"
            )

            decision = "PENDING" if requires_approval else "ALLOW"

            req_id = str(uuid.uuid4())

            conn.execute(
                '''INSERT INTO action_logs
                   (id, sender, task, amount, decision, law, ts, chain, intent, audit_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    req_id,
                    html.escape(req.sender_id),
                    html.escape(req.task),
                    str(amount_dec),
                    decision,
                    audit_report.get('grounded_law', 'N/A'),
                    now,
                    req.chain,
                    html.escape(req.intent),
                    audit_report.get('audit_id', '')
                )
            )

            if decision == "PENDING":
                conn.execute(
                    'INSERT INTO pending (id, status, request_json, version, created_at) VALUES (?, ?, ?, ?, ?)',
                    (req_id, "WAITING", req.model_dump_json(), UAIP_VERSION, now)
                )
                logger.info(f"Transaction pending approval: {req_id} (amount=${amount_dec})")
                return {
                    "status": "PENDING_APPROVAL",
                    "request_id": req_id,
                    "message": "High-value transaction requires human approval"
                }

            try:
                amount_normalized = normalize_amount(amount_dec, req.chain)
                settlement_result = UAIPFinancialEngine().process_settlement(
                    req.sender_id,
                    amount_normalized,
                    SETTLEMENT_PROVIDER,
                    req.chain
                )
                logger.info(f"Transaction successful: {req_id} - ${amount_normalized} on {req.chain}")
                return {
                    "status": "SUCCESS",
                    "request_id": req_id,
                    "settlement": settlement_result
                }
            except Exception as e:
                logger.error(f"Settlement failed for {req_id}: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail="Settlement processing failed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transaction execution error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Transaction failed")

@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    x_session_token: Optional[str] = Header(None, alias="X-Session-Token")
):
    """SECURITY FIX: Protected admin dashboard"""
    client_ip = get_client_ip(request)
    
    if not x_session_token or not validate_admin_session(x_session_token, client_ip):
        return get_login_page()
    
    rows = ""
    stats = {"total": 0, "pending": 0, "allowed": 0, "blocked": 0}

    try:
        with db_session() as conn:
            logs_data = conn.execute(
                'SELECT * FROM action_logs ORDER BY ts DESC LIMIT 50'
            ).fetchall()

            for l in logs_data:
                stats["total"] += 1

                d_sender = html.escape(str(l['sender'] if l['sender'] else 'Unknown'))[:100]
                d_task = html.escape(str(l['task'] if l['task'] else 'Unknown'))[:200]
                d_amount = html.escape(str(l['amount'] if l['amount'] else '0.0'))
                d_decision = str(l['decision'] if l['decision'] else 'UNKNOWN')
                d_law = html.escape(str(l['law'] if l['law'] else 'N/A'))[:300]
                d_ts = datetime.fromtimestamp(l['ts'] if l['ts'] else 0).strftime('%Y-%m-%d %H:%M:%S')

                if d_decision == "PENDING":
                    stats["pending"] += 1
                elif d_decision in ["ALLOW", "HUMAN_APPROVED"]:
                    stats["allowed"] += 1
                elif d_decision == "BLOCKED":
                    stats["blocked"] += 1

                color = "green" if d_decision in ["ALLOW", "HUMAN_APPROVED"] else ("red" if d_decision == "BLOCKED" else "orange")
                action_ui = f"<button onclick=\"auth('{html.escape(str(l['id']))}')\">Approve</button>" if d_decision == "PENDING" else "✅ PAID"

                rows += f"""
                <tr>
                    <td style='font-size: 0.8em;'>{d_ts}</td>
                    <td title='{d_sender}'>{d_sender[:30]}...</td>
                    <td>{d_task[:50]}...</td>
                    <td><b>${d_amount}</b></td>
                    <td style='color:{color};font-weight:bold;'>{d_decision}</td>
                    <td style='font-size: 0.85em; color: #8b949e;'>{d_law[:100]}...</td>
                    <td>{action_ui}</td>
                </tr>
                """
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        rows = f"<tr><td colspan='7' style='color:red;'>Error loading data</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AgentGuard Dashboard</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    background: linear-gradient(135deg, #0d1117 0%, #1a1f2e 100%);
                    color: #e6edf3;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    padding: 20px;
                }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                h1 {{
                    font-size: 2em;
                    margin-bottom: 20px;
                    color: #58a6ff;
                    text-shadow: 0 0 10px rgba(88, 166, 255, 0.3);
                }}
                .controls {{
                    margin-bottom: 20px;
                    display: flex;
                    gap: 10px;
                    justify-content: space-between;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 30px;
                }}
                .stat-card {{
                    background: rgba(255,255,255,0.05);
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid rgba(88, 166, 255, 0.2);
                }}
                .stat-card h3 {{ color: #8b949e; font-size: 0.9em; margin-bottom: 10px; }}
                .stat-card .value {{ font-size: 2em; font-weight: bold; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    background: rgba(13, 17, 23, 0.6);
                    border-radius: 8px;
                    overflow: hidden;
                }}
                thead {{ background: rgba(88, 166, 255, 0.1); }}
                td, th {{
                    padding: 12px;
                    border-bottom: 1px solid rgba(48, 54, 61, 0.8);
                    text-align: left;
                }}
                tr:hover {{ background: rgba(88, 166, 255, 0.05); }}
                button {{
                    background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    cursor: pointer;
                    border-radius: 6px;
                    font-weight: 600;
                    transition: all 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(35, 134, 54, 0.4);
                }}
                button:disabled {{
                    opacity: 0.5;
                    cursor: not-allowed;
                }}
                .logout-btn {{
                    background: rgba(248, 81, 73, 0.2);
                }}
                .refresh-btn {{
                    background: rgba(88, 166, 255, 0.2);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ AgentGuard Master Dashboard</h1>

                <div class="controls">
                    <button class="refresh-btn" onclick="toggleRefresh()">⏸️ Pause Auto-Refresh</button>
                    <button class="logout-btn" onclick="logout()">Logout</button>
                </div>

                <div class="stats">
                    <div class="stat-card">
                        <h3>Total Transactions</h3>
                        <div class="value" style="color:#58a6ff;">{stats['total']}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Pending Approval</h3>
                        <div class="value" style="color:#f0883e;">{stats['pending']}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Approved</h3>
                        <div class="value" style="color:#3fb950;">{stats['allowed']}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Blocked</h3>
                        <div class="value" style="color:#f85149;">{stats['blocked']}</div>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Agent DID</th>
                            <th>Intent</th>
                            <th>Value</th>
                            <th>Status</th>
                            <th>Legal Grounding</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>

            <script>
                let autoRefresh = true;
                let refreshInterval;

                function getSessionToken() {{
                    return localStorage.getItem('admin_session');
                }}

                function toggleRefresh() {{
                    autoRefresh = !autoRefresh;
                    const btn = event.target;

                    if (autoRefresh) {{
                        btn.textContent = '⏸️ Pause Auto-Refresh';
                        refreshInterval = setInterval(() => location.reload(), 10000);
                    }} else {{
                        btn.textContent = '▶️ Resume Auto-Refresh';
                        clearInterval(refreshInterval);
                    }}
                }}

                async function logout() {{
                    const token = getSessionToken();
                    
                    try {{
                        await fetch('/v1/admin/logout', {{
                            method: 'POST',
                            headers: {{ 'X-Session-Token': token }}
                        }});
                    }} catch(e) {{
                        console.error('Logout error:', e);
                    }}
                    
                    localStorage.removeItem('admin_session');
                    location.reload();
                }}

                async function auth(id) {{
                    const token = getSessionToken();
                    if(!token) {{
                        alert('Session expired. Please login again.');
                        location.reload();
                        return;
                    }}

                    const btn = event.target;
                    btn.disabled = true;
                    btn.textContent = 'Processing...';

                    try {{
                        const res = await fetch('/v1/decision/' + encodeURIComponent(id) + '/allow', {{
                            method: 'POST',
                            headers: {{ 'X-Session-Token': token }}
                        }});

                        if(!res.ok) {{
                            if(res.status === 401) {{
                                alert('❌ Session expired. Please login again.');
                                localStorage.removeItem('admin_session');
                                location.reload();
                                return;
                            }}
                            const error = await res.json();
                            alert('❌ Error: ' + (error.detail || 'Unauthorized'));
                            btn.disabled = false;
                            btn.textContent = 'Approve';
                            return;
                        }}

                        const d = await res.json();
                        if(d.status === 'SETTLED') {{
                            alert('✅ Success: Funds Released');
                            location.reload();
                        }} else {{
                            alert('❌ Unexpected response: ' + JSON.stringify(d));
                            btn.disabled = false;
                            btn.textContent = 'Approve';
                        }}
                    }} catch(e) {{
                        alert('❌ Request failed: ' + e.message);
                        btn.disabled = false;
                        btn.textContent = 'Approve';
                    }}
                }}

                // Check if we have a valid session
                const token = getSessionToken();
                if (!token) {{
                    location.reload();
                }}

                // Start auto-refresh
                refreshInterval = setInterval(() => location.reload(), 10000);
            </script>
        </body>
    </html>
    """

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(
    request: Request,
    req_id: str = Path(..., regex=r'^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}),
    choice: str = Path(..., regex=r'^(allow|deny)),
    x_session_token: Optional[str] = Header(None, alias="X-Session-Token")
):
    """SECURITY FIX: Session-based manual approval"""
    client_ip = get_client_ip(request)
    
    if not x_session_token or not validate_admin_session(x_session_token, client_ip):
        logger.warning(f"Unauthorized admin access attempt from {client_ip}")
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        with db_session() as conn:
            cursor = conn.execute(
                'UPDATE pending SET status=?, approved_by=?, approved_at=? WHERE id=? AND status="WAITING"',
                ("APPROVED" if choice == "allow" else "REJECTED", "admin", time.time(), req_id)
            )

            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Transaction not found or already processed")

            if choice != "allow":
                conn.execute('UPDATE action_logs SET decision="BLOCKED" WHERE id=?', (req_id,))
                logger.info(f"Transaction {req_id} rejected by admin")
                return {"status": "REJECTED"}

            txn = conn.execute(
                'SELECT request_json FROM pending WHERE id=?',
                (req_id,)
            ).fetchone()

            if not txn:
                raise HTTPException(status_code=404, detail="Transaction data not found")

            try:
                r = UAIPPacket.parse_raw(txn['request_json'])
            except Exception as e:
                logger.error(f"Invalid pending request data for {req_id}: {e}")
                raise HTTPException(status_code=500, detail="Corrupted transaction data")

            try:
                amount_normalized = normalize_amount(Decimal(r.amount), r.chain)
                settlement_result = UAIPFinancialEngine().process_settlement(
                    r.sender_id,
                    amount_normalized,
                    SETTLEMENT_PROVIDER,
                    r.chain
                )

                conn.execute(
                    'UPDATE action_logs SET decision="HUMAN_APPROVED" WHERE id=?',
                    (req_id,)
                )

                logger.info(f"Transaction {req_id} approved by admin: ${amount_normalized} on {r.chain}")
                return {"status": "SETTLED", "settlement": settlement_result}

            except Exception as e:
                logger.error(f"Settlement failed for approved transaction {req_id}: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail="Settlement processing failed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Manual decision error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Decision processing failed")

@app.get("/v1/check/{req_id}")
async def check(req_id: str = Path(..., regex=r'^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})):
    """Check status of a pending transaction"""
    try:
        with db_session() as conn:
            res = conn.execute(
                'SELECT status FROM pending WHERE id=?',
                (req_id,)
            ).fetchone()

            return {
                "status": res['status'] if res else "NOT_FOUND",
                "request_id": req_id
            }
    except Exception as e:
        logger.error(f"Status check error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Status check failed")

@app.get("/health")
async def health():
    """Health check endpoint"""
    try:
        with db_session() as conn:
            conn.execute('SELECT 1').fetchone()
        return {"status": "healthy", "version": UAIP_VERSION}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting UAIP Gateway v{UAIP_VERSION}")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")