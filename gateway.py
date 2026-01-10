from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, validator, Field
from decimal import Decimal, InvalidOperation
from contextlib import contextmanager
import uuid, time, json, html, os, sqlite3, threading, secrets, logging
import nacl.signing, nacl.encoding
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import re

# --- INTERNAL SYSTEM IMPORTS ---
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('uaip_gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UAIP Master Gateway",
    version="1.0.0",
    docs_url=None,  # Disable in production
    redoc_url=None  # Disable in production
)

# --- SECURITY MIDDLEWARE ---
# Add CORS protection
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Add trusted host protection
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,*.uaip.io").split(",")
)

# --- CONFIGURATION ---
ADMIN_KEY = os.getenv("ADMIN_KEY")
if not ADMIN_KEY or len(ADMIN_KEY) < 32:
    logger.critical("ADMIN_KEY must be set with minimum 32 characters!")
    raise RuntimeError("Insecure ADMIN_KEY configuration")

DB_PATH = os.getenv("DB_PATH", "uaip_vault.db")
UAIP_VERSION = "1.0.0"

# Security Constants
MAX_AMOUNT = Decimal("1000000000")  # $1B max
MIN_AMOUNT = Decimal("0.01")  # $0.01 min
MAX_TASK_LENGTH = 5000
MAX_INTENT_LENGTH = 2000
MAX_DID_LENGTH = 500
NONCE_EXPIRY_SECONDS = 120
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100
LOCKOUT_DURATION = 300  # 5 minutes
MAX_FAILED_ATTEMPTS = 5

# Supported chains (whitelist)
SUPPORTED_CHAINS = {"BASE", "SOLANA", "ETHEREUM", "POLYGON"}

# --- 2. DATA MODELS WITH VALIDATION ---
class UAIPPacket(BaseModel):
    sender_id: str = Field(..., max_length=MAX_DID_LENGTH)
    task: str = Field(..., max_length=MAX_TASK_LENGTH)
    amount: str = Field(..., regex=r'^\d+(\.\d{1,18})?$')  # Decimal validation
    chain: str = Field(..., max_length=50)
    intent: str = Field(..., max_length=MAX_INTENT_LENGTH)
    data: dict
    signature: str = Field(..., regex=r'^[0-9a-fA-F]+$')  # Hex only
    public_key: str = Field(..., regex=r'^[0-9a-fA-F]+$')  # Hex only
    nonce: str = Field(..., regex=r'^[0-9a-f\-]+$')  # UUID format
    timestamp: float
    zk_proof: dict

    @validator('chain')
    def validate_chain(cls, v):
        if v.upper() not in SUPPORTED_CHAINS:
            raise ValueError(f'Chain must be one of {SUPPORTED_CHAINS}')
        return v.upper()

    @validator('timestamp')
    def validate_timestamp(cls, v):
        now = time.time()
        # Allow 5 minute clock skew
        if abs(v - now) > 300:
            raise ValueError('Timestamp too far from current time')
        return v

    @validator('amount')
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

class RegistrationRequest(BaseModel):
    registration_data: dict
    signature: str = Field(..., regex=r'^[0-9a-fA-F]+$')
    public_key: str = Field(..., regex=r'^[0-9a-fA-F]+$')

# --- 3. DATABASE ARCHITECTURE ---
@contextmanager
def db_session():
    """Thread-safe database connection with proper error handling."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=20, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA foreign_keys=ON;')  # Enforce referential integrity
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="Database error")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize database with proper schema and indexes."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            
            # Inventory table with constraints
            c.execute('''CREATE TABLE IF NOT EXISTS inventory (
                did TEXT PRIMARY KEY CHECK(length(did) <= 500),
                pk TEXT NOT NULL CHECK(length(pk) <= 1000),
                zk_commitment TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (julianday('now')),
                updated_at REAL NOT NULL DEFAULT (julianday('now'))
            )''')
            
            # Nonces table with index
            c.execute('''CREATE TABLE IF NOT EXISTS nonces (
                id TEXT PRIMARY KEY CHECK(length(id) <= 100),
                ts REAL NOT NULL,
                sender_id TEXT
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_nonces_ts ON nonces(ts)')
            
            # Pending transactions
            c.execute('''CREATE TABLE IF NOT EXISTS pending (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK(status IN ('WAITING', 'APPROVED', 'REJECTED')),
                request_json TEXT NOT NULL,
                version TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (julianday('now')),
                approved_by TEXT,
                approved_at REAL
            )''')
            
            # Rate limiting and lockouts
            c.execute('''CREATE TABLE IF NOT EXISTS lockouts (
                ip TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until REAL,
                last_attempt REAL
            )''')
            
            # Action logs with better schema
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
            
            # Blacklist with reason
            c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
                did TEXT PRIMARY KEY,
                reason TEXT,
                ts REAL NOT NULL,
                blocked_by TEXT
            )''')
            
            # Rate limiting table
            c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
                identifier TEXT NOT NULL,
                window_start REAL NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (identifier, window_start)
            )''')
            
            conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.critical(f"Failed to initialize database: {e}")
        raise

init_db()

# --- 4. SECURITY UTILITIES ---
def get_client_ip(request: Request) -> str:
    """Extract client IP with proxy support."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def check_rate_limit(identifier: str, max_requests: int = RATE_LIMIT_MAX_REQUESTS) -> bool:
    """
    Check if identifier has exceeded rate limit.
    Returns True if within limit, False if exceeded.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    
    try:
        with db_session() as conn:
            # Clean old windows
            conn.execute('DELETE FROM rate_limits WHERE window_start < ?', (window_start,))
            
            # Get current count
            current = conn.execute(
                'SELECT request_count FROM rate_limits WHERE identifier=? AND window_start > ?',
                (identifier, window_start)
            ).fetchone()
            
            count = sum(row['request_count'] for row in (current or []))
            
            if count >= max_requests:
                logger.warning(f"Rate limit exceeded for {identifier}")
                return False
            
            # Increment counter
            conn.execute(
                'INSERT OR REPLACE INTO rate_limits (identifier, window_start, request_count) VALUES (?, ?, ?)',
                (identifier, int(now), count + 1)
            )
            
            return True
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")
        return True  # Fail open to avoid blocking legitimate traffic

def check_lockout(ip: str) -> bool:
    """Check if IP is locked out. Returns True if locked, False otherwise."""
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
                    # Lockout expired, reset
                    conn.execute('DELETE FROM lockouts WHERE ip=?', (ip,))
            
            return False
    except Exception as e:
        logger.error(f"Lockout check failed: {e}")
        return False

def record_failed_attempt(ip: str):
    """Record failed authentication attempt and apply lockout if threshold exceeded."""
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
        logger.error(f"Failed to record attempt: {e}")

def sanitize_did(did: str) -> str:
    """Sanitize DID for safe storage and display."""
    # Remove any potential SQL injection or XSS
    did = html.escape(did.strip())
    # Ensure reasonable length
    return did[:MAX_DID_LENGTH]

# --- 5. MAINTENANCE ---
def cleanup_task():
    """Background task for database maintenance."""
    while True:
        try:
            with db_session() as conn:
                # Clean expired nonces
                conn.execute('DELETE FROM nonces WHERE ts < ?', (time.time() - NONCE_EXPIRY_SECONDS,))
                
                # Clean old action logs (keep 30 days)
                conn.execute('DELETE FROM action_logs WHERE ts < ?', (time.time() - 2592000,))
                
                # Clean old rate limit records
                conn.execute('DELETE FROM rate_limits WHERE window_start < ?', (time.time() - RATE_LIMIT_WINDOW,))
                
                # Clean expired lockouts
                conn.execute('DELETE FROM lockouts WHERE lockout_until < ? AND lockout_until IS NOT NULL', (time.time(),))
                
                logger.debug("Cleanup task completed")
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
        
        time.sleep(60)

cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
cleanup_thread.start()

# --- 6. ENDPOINTS ---

@app.post("/v1/register")
async def register(request: Request, req: RegistrationRequest):
    """Register a new agent with cryptographic verification."""
    client_ip = get_client_ip(request)
    
    # Check lockout
    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
    
    # Check rate limit
    if not check_rate_limit(f"register:{client_ip}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    try:
        data = req.registration_data
        sig = req.signature
        pk = req.public_key
        
        # Validate registration data
        if not data.get("agent_id") or not data.get("zk_commitment"):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        agent_id = sanitize_did(data["agent_id"])
        
        # Verify signature
        try:
            vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
            msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk.verify(msg, bytes.fromhex(sig))
        except Exception as e:
            logger.warning(f"Signature verification failed for {agent_id}: {e}")
            record_failed_attempt(client_ip)
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Store in database
        with db_session() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO inventory (did, pk, zk_commitment, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
                (agent_id, pk, str(data["zk_commitment"]), time.time(), time.time())
            )
        
        logger.info(f"Agent registered: {agent_id}")
        return {"status": "REGISTERED", "agent_id": agent_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/v1/execute")
async def execute(request: Request, req: UAIPPacket):
    """Execute agent transaction with multi-layer security validation."""
    client_ip = get_client_ip(request)
    now = time.time()
    
    # Check lockout
    if check_lockout(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts")
    
    # Check rate limit
    if not check_rate_limit(f"execute:{req.sender_id}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    try:
        amount_dec = Decimal(req.amount)
        auditor = ComplianceAuditor()
        
        with db_session() as conn:
            # 1. Check blacklist
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
            
            # 2. Check nonce (replay protection)
            try:
                conn.execute(
                    'INSERT INTO nonces (id, ts, sender_id) VALUES (?, ?, ?)',
                    (req.nonce, now, req.sender_id)
                )
            except sqlite3.IntegrityError:
                logger.warning(f"Replay attack detected: {req.nonce}")
                record_failed_attempt(client_ip)
                raise HTTPException(status_code=403, detail="REPLAY_ATTACK_DETECTED")
            
            # 3. Verify cryptographic identity
            try:
                vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
                msg = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                vk.verify(msg, bytes.fromhex(req.signature))
                
                # Verify agent is registered
                agent = conn.execute(
                    'SELECT zk_commitment FROM inventory WHERE did=? AND pk=?',
                    (req.sender_id, req.public_key)
                ).fetchone()
                
                if not agent:
                    raise Exception("Agent not registered")
                
                # Verify ZK proof
                if not ZK_Privacy.verify_proof(req.zk_proof, int(agent['zk_commitment'])):
                    raise Exception("ZK proof verification failed")
                    
            except Exception as e:
                logger.warning(f"Identity verification failed for {req.sender_id}: {e}")
                record_failed_attempt(client_ip)
                raise HTTPException(status_code=401, detail="IDENTITY_VERIFICATION_FAILED")
            
            # 4. Run compliance audit
            audit_log = {
                "sender": req.sender_id,
                "task": req.task,
                "amount": str(amount_dec),
                "chain": req.chain,
                "intent": req.intent,
                "timestamp": now
            }
            
            audit_status, audit_report = auditor.run_active_audit(audit_log)
            
            # 5. Handle blocked transactions
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
            
            # 6. Determine approval workflow
            requires_approval = (
                amount_dec >= Decimal("1000") or
                audit_status == "PENDING_ENFORCED"
            )
            
            decision = "PENDING" if requires_approval else "ALLOW"
            
            # 7. Log transaction
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
            
            # 8. Handle pending transactions
            if decision == "PENDING":
                conn.execute(
                    'INSERT INTO pending (id, status, request_json, version, created_at) VALUES (?, ?, ?, ?, ?)',
                    (req_id, "WAITING", req.json(), UAIP_VERSION, now)
                )
                logger.info(f"Transaction pending approval: {req_id}")
                return {
                    "status": "PENDING_APPROVAL",
                    "request_id": req_id,
                    "message": "High-value transaction requires human approval"
                }
            
            # 9. Process settlement
            try:
                settlement_result = UAIPFinancialEngine().process_settlement(
                    req.sender_id,
                    amount_dec,
                    "provider_01",
                    req.chain
                )
                logger.info(f"Transaction successful: {req_id} - ${amount_dec}")
                return {
                    "status": "SUCCESS",
                    "request_id": req_id,
                    "settlement": settlement_result
                }
            except Exception as e:
                logger.error(f"Settlement failed: {e}")
                raise HTTPException(status_code=500, detail="Settlement processing failed")
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transaction execution error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Transaction failed")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Admin dashboard with security-hardened rendering."""
    rows = ""
    stats = {"total": 0, "pending": 0, "allowed": 0, "blocked": 0}
    
    try:
        with db_session() as conn:
            logs_data = conn.execute(
                'SELECT * FROM action_logs ORDER BY ts DESC LIMIT 50'
            ).fetchall()
            
            for l in logs_data:
                stats["total"] += 1
                
                # Safe data extraction with defaults
                d_sender = html.escape(str(l.get('sender', 'Unknown')))[:100]
                d_task = html.escape(str(l.get('task', 'Unknown')))[:200]
                d_amount = html.escape(str(l.get('amount', '0.0')))
                d_decision = str(l.get('decision', 'UNKNOWN'))
                d_law = html.escape(str(l.get('law', 'N/A')))[:300]
                d_ts = datetime.fromtimestamp(l.get('ts', 0)).strftime('%Y-%m-%d %H:%M:%S')
                
                # Update stats
                if d_decision == "PENDING":
                    stats["pending"] += 1
                elif d_decision in ["ALLOW", "HUMAN_APPROVED"]:
                    stats["allowed"] += 1
                elif d_decision == "BLOCKED":
                    stats["blocked"] += 1
                
                color = "green" if d_decision in ["ALLOW", "HUMAN_APPROVED"] else ("red" if d_decision == "BLOCKED" else "orange")
                action_ui = f"<button onclick=\"auth('{html.escape(l['id'])}')\">Approve</button>" if d_decision == "PENDING" else "✅ PAID"
                
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
        rows = f"<tr><td colspan='7' style='color:red;'>Error loading data. Check logs for details.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="refresh" content="10">
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
                .badge {{ 
                    padding: 4px 8px; 
                    border-radius: 4px; 
                    font-size: 0.85em;
                    font-weight: 600;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ AgentGuard Master Dashboard</h1>
                
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
                            <th>Legal Grounding (RAG)</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            
            <script>
                async function auth(id) {{
                    const k = prompt('Enter Admin Key:');
                    if(!k) return;
                    
                    try {{
                        const res = await fetch('/v1/decision/' + encodeURIComponent(id) + '/allow', {{ 
                            method: 'POST', 
                            headers: {{ 'X-Admin-Key': k }}
                        }});
                        
                        if(!res.ok) {{
                            const error = await res.json();
                            alert('❌ Error: ' + (error.detail || 'Unauthorized'));
                            return;
                        }}
                        
                        const d = await res.json();
                        if(d.status === 'SETTLED') {{ 
                            alert('✅ Success: Funds Released'); 
                            location.reload(); 
                        }} else {{ 
                            alert('❌ Unexpected response: ' + JSON.stringify(d)); 
                        }}
                    }} catch(e) {{
                        alert('❌ Request failed: ' + e.message);
                    }}
                }}
            </script>
