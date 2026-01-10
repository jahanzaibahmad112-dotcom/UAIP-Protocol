from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator
from decimal import Decimal
from contextlib import contextmanager
import uuid, time, json, html, os, sqlite3, threading, secrets, logging
import nacl.signing, nacl.encoding
from typing import Optional, Dict, Any, List

# --- INTERNAL SYSTEM IMPORTS ---
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

# --- 1. LOGGING & SECURITY CONFIG ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="UAIP Master Gateway v2.0")

# Security Middlewares
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

ADMIN_KEY = os.getenv("ADMIN_KEY", "uaip-secret-key-must-be-very-long")
DB_PATH = "uaip_vault.db"
UAIP_VERSION = "1.0.0"

# --- 2. DATA MODELS (Strict Validation) ---
class UAIPPacket(BaseModel):
    sender_id: str = Field(..., max_length=500)
    task: str = Field(..., max_length=5000)
    amount: str # Sent as string to prevent float rounding
    chain: str = Field(..., max_length=50)
    intent: str = Field(..., max_length=2000)
    data: dict
    signature: str
    public_key: str
    nonce: str
    timestamp: float
    zk_proof: dict

    @field_validator('amount')
    @classmethod
    def validate_amount(cls, v):
        try:
            amt = Decimal(v)
            if amt < Decimal("0.01"): raise ValueError("Min $0.01")
            return v
        except: raise ValueError("Invalid Amount")

class RegistrationRequest(BaseModel):
    registration_data: dict
    signature: str
    public_key: str

# --- 3. DATABASE ARCHITECTURE (The Fortress) ---
@contextmanager
def db_session():
    conn = sqlite3.connect(DB_PATH, timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;') # High-speed concurrent mode
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS inventory (did TEXT PRIMARY KEY, pk TEXT, zk_commitment TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, ts REAL, sender_id TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, status TEXT, request_json TEXT, v TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS action_logs (id TEXT PRIMARY KEY, sender TEXT, task TEXT, amount TEXT, decision TEXT, law TEXT, ts REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS blacklist (did TEXT PRIMARY KEY, reason TEXT, ts REAL)')

init_db()

# --- 4. ENDPOINTS ---

@app.post("/v1/register")
async def register(req: RegistrationRequest):
    try:
        data, sig, pk = req.registration_data, req.signature, req.public_key
        vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(sig))
        
        with db_session() as conn:
            conn.execute('INSERT OR REPLACE INTO inventory VALUES (?, ?, ?)', 
                         (data["agent_id"], pk, str(data["zk_commitment"])))
        return {"status": "REGISTERED"}
    except: raise HTTPException(status_code=401, detail="IDENTITY_VERIFICATION_FAILED")

@app.post("/v1/execute")
async def execute(req: UAIPPacket):
    now = time.time()
    amount_dec = Decimal(req.amount)

    with db_session() as conn:
        # A. Identity & Replay Gates
        if conn.execute('SELECT did FROM blacklist WHERE did=?', (req.sender_id,)).fetchone():
            raise HTTPException(status_code=403, detail="TERMINATED")
        
        try:
            conn.execute('INSERT INTO nonces VALUES (?, ?, ?)', (req.nonce, now, req.sender_id))
        except: raise HTTPException(status_code=403, detail="REPLAY_DETECTED")

        # B. Ed25519 & ZK Verification
        try:
            vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
            msg = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk.verify(msg, bytes.fromhex(req.signature))
            
            agent = conn.execute('SELECT zk_commitment FROM inventory WHERE did=?', (req.sender_id,)).fetchone()
            if not agent or not ZK_Privacy.verify_proof(req.zk_proof, int(agent['zk_commitment'])): raise Exception()
        except: raise HTTPException(status_code=401, detail="ZERO_TRUST_AUTH_FAILED")

        # C. COMPLIANCE ACTIVE ENFORCEMENT (The Enforcer Hook)
        auditor = ComplianceAuditor()
        audit_status, audit_report = auditor.run_active_audit({
            "sender": req.sender_id, "task": req.task, "amount": req.amount, "chain": req.chain
        })

        if audit_status == "TERMINATE":
            conn.execute('INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?)', (req.sender_id, "Policy Violation", now))
            raise HTTPException(status_code=451, detail="IDENTITY_REVOKED_BY_ENFORCER")

        # D. Governance Logic (Tiered HITL)
        # Nano-bypass: Under $10 is auto-approved unless enforcer says otherwise
        decision = "PENDING" if (amount_dec >= 1000 or audit_status == "PENDING_ENFORCED") else "ALLOW"
        if amount_dec < 10: decision = "ALLOW"

        req_id = str(uuid.uuid4())[:8]
        conn.execute('INSERT INTO action_logs VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (req_id, html.escape(req.sender_id), html.escape(req.task), str(amount_dec), decision, audit_report.get('grounded_law', 'SOC2'), now))

        if decision == "PENDING":
            conn.execute('INSERT INTO pending VALUES (?, ?, ?, ?)', (req_id, "WAITING", req.model_dump_json(), UAIP_VERSION))
            return {"status": "PAUSED", "request_id": req_id}

        # E. Settlement (The Profit Logic)
        bank = UAIPFinancialEngine()
        settlement = bank.process_settlement(req.sender_id, amount_dec, "provider_node_1", req.chain)
        return {"status": "SUCCESS", "tx_id": settlement['tx_id']}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with db_session() as conn:
        logs = conn.execute('SELECT * FROM action_logs ORDER BY ts DESC LIMIT 15').fetchall()
    
    rows = "".join([f"<tr><td>{l['sender']}</td><td>{l['task']}</td><td><b>${l['amount']}</b></td><td style='color:{'green' if l['decision'] in ['ALLOW','HUMAN_APPROVED'] else 'orange'}'>{l['decision']}</td><td><small>{l['law']}</small></td><td><button onclick=\"auth('{l['id']}')\">Approve</button></td></tr>" for l in logs])
    return f"""
    <html>
        <head><meta http-equiv='refresh' content='5'><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:40px;}} table{{width:100%;border-collapse:collapse;}} td{{padding:10px;border-bottom:1px solid #333;}} button{{background:#238636;color:white;border:none;padding:8px;cursor:pointer;border-radius:4px;}}</style></head>
        <body>
            <h1>🛡️ UAIP Master Command Center</h1>
            <p>Node: Secure-Ultima | Compliance: RAG-Active | Status: 0.5% Revenue Enabled</p>
            <table><thead><tr><th>DID</th><th>Task</th><th>Value</th><th>Decision</th><th>Legal Grounding</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table>
            <script>
                async function auth(id) {{
                    const k = prompt('Enter Admin Key:');
                    if(!k) return;
                    const res = await fetch('/v1/decision/'+id+'/allow', {{ method:'POST', headers:{{'X-Admin-Key':k}} }});
                    const d = await res.json();
                    if(d.status === 'SETTLED') {{ alert('✅ Payment Executed'); location.reload(); }}
                    else {{ alert('❌ Denied'); }}
                }}
            </script>
        </body>
    </html>"""

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str, x_admin_key: str = Header(None)):
    if not secrets.compare_digest(x_admin_key or "", ADMIN_KEY): raise HTTPException(status_code=401)
    
    with db_session() as conn:
        # Atomic Lock: Prevent Double-Spending
        cursor = conn.execute('UPDATE pending SET status="APPROVED" WHERE id=? AND status="WAITING"', (req_id,))
        if cursor.rowcount == 0 or choice != "allow": raise HTTPException(status_code=400, detail="STALE_OR_INVALID")

        txn = conn.execute('SELECT request_json FROM pending WHERE id=?', (req_id,)).fetchone()
        r = json.loads(txn['request_json'])
        
        # Execute actual banking settlement
        UAIPFinancialEngine().process_settlement(r['sender_id'], Decimal(r['amount']), "provider_01", r['chain'])
        conn.execute('UPDATE action_logs SET decision="HUMAN_APPROVED" WHERE id=?', (req_id,))

    return {"status": "SETTLED"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    with db_session() as conn:
        res = conn.execute('SELECT status FROM pending WHERE id=?', (req_id,)).fetchone()
        return {"status": res['status'] if res else "PENDING"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
