from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from decimal import Decimal
from contextlib import contextmanager
import uuid, time, json, html, os, sqlite3, threading, secrets
import nacl.signing, nacl.encoding

# --- INTERNAL SYSTEM IMPORTS ---
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

app = FastAPI(title="UAIP Fortress-Ultima v3")

# --- 1. CONFIGURATION & SECURITY ---
ADMIN_KEY = os.getenv("ADMIN_KEY", "uaip-secret-123")
# NEW: Developer/Corporate IP Whitelist to prevent shared-office lockouts
WHITELIST_IPS = os.getenv("ADMIN_IP_WHITELIST", "127.0.0.1").split(",")
# NEW: Data Schema Version for future-proofing
UAIP_PROTOCOL_VERSION = "1.0.0"

DB_PATH = "uaip_vault.db"

# --- 2. DATABASE ARCHITECTURE ---
@contextmanager
def db_session():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;') 
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
        c.execute('CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, ts REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, status TEXT, request_json TEXT, version TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS lockouts (ip TEXT PRIMARY KEY, attempts INTEGER, lockout_until REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS action_logs (id TEXT PRIMARY KEY, sender TEXT, task TEXT, amount TEXT, decision TEXT, chain TEXT, ts REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS blacklist (did TEXT PRIMARY KEY, ts REAL)')

init_db()

# --- 3. MAINTENANCE (Autonomous Garbage Collector) ---
def start_garbage_collector():
    def cleanup():
        while True:
            try:
                with db_session() as conn:
                    conn.execute('DELETE FROM nonces WHERE ts < ?', (time.time() - 120,))
                    conn.execute('DELETE FROM action_logs WHERE ts < ?', (time.time() - 86400,))
            except: pass
            time.sleep(60)
    threading.Thread(target=cleanup, daemon=True).start()

start_garbage_collector()

# --- 4. DATA MODELS ---
class UAIPPacket(BaseModel):
    sender_id: str; task: str; amount: str; chain: str; intent: str; data: dict
    signature: str; public_key: str; nonce: str; timestamp: float; zk_proof: dict

# --- 5. SECURE ENDPOINTS ---

@app.post("/v1/register")
async def register(req: dict):
    try:
        data, sig, pk = req["registration_data"], req["signature"], req["public_key"]
        vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(sig))
        
        with db_session() as conn:
            conn.execute('INSERT OR REPLACE INTO inventory VALUES (?, ?, ?)', 
                         (data["agent_id"], pk, str(data["zk_commitment"])))
        return {"status": "IDENTITY_VERIFIED", "v": UAIP_PROTOCOL_VERSION}
    except: raise HTTPException(status_code=401, detail="AUTH_FAILURE")

@app.post("/v1/execute")
async def execute(req: UAIPPacket):
    now = time.time()
    amount_dec = Decimal(req.amount) 

    with db_session() as conn:
        is_blocked = conn.execute('SELECT did FROM blacklist WHERE did=?', (req.sender_id,)).fetchone()
        if is_blocked: raise HTTPException(status_code=403, detail="TERMINATED")
        if now - req.timestamp > 60: raise HTTPException(status_code=403, detail="EXPIRED")
        
        try:
            conn.execute('INSERT INTO nonces VALUES (?, ?)', (req.nonce, now))
        except sqlite3.IntegrityError: raise HTTPException(status_code=403, detail="REPLAY")

        try:
            vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
            msg_payload = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk.verify(msg_payload, bytes.fromhex(req.signature))
            
            agent = conn.execute('SELECT zk_commitment FROM inventory WHERE did=?', (req.sender_id,)).fetchone()
            if not agent or not ZK_Privacy.verify_proof(req.zk_proof, int(agent['zk_commitment'])): raise Exception()
        except: raise HTTPException(status_code=401, detail="CRYPTO_FAIL")

        sanitized_task = html.escape(req.task).strip()
        auditor = ComplianceAuditor()
        audit_decision, _ = auditor.run_active_audit({"sender": req.sender_id, "task": sanitized_task, "amount": req.amount})

        if audit_decision == "TERMINATE":
            conn.execute('INSERT OR REPLACE INTO blacklist VALUES (?, ?)', (req.sender_id, now))
            raise HTTPException(status_code=451, detail="LEGAL_TERMINATION")

        decision = "PENDING" if amount_dec >= 1000 or audit_decision == "PENDING_ENFORCED" else "ALLOW"
        req_id = str(uuid.uuid4())[:8]
        
        conn.execute('INSERT INTO action_logs (id, sender, task, amount, decision, chain, ts) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (req_id, html.escape(req.sender_id), sanitized_task, str(amount_dec), decision, req.chain, now))

        if decision == "PENDING":
            # NEW: Versioned JSON storage to prevent future parsing crashes
            conn.execute('INSERT INTO pending (id, status, request_json, version) VALUES (?, ?, ?, ?)', 
                         (req_id, "WAITING", req.json(), UAIP_PROTOCOL_VERSION))
            return {"status": "PAUSED", "request_id": req_id}

        bank = UAIPFinancialEngine()
        bank.process_settlement(req.sender_id, amount_dec, "provider_node_1", req.chain)
        
        return {"status": "SUCCESS"}

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(request: Request, req_id: str, choice: str, x_admin_key: str = Header(None)):
    client_ip = request.client.host
    now = time.time()
    
    with db_session() as conn:
        # 1. FIXED BRUTE FORCE (With IP Whitelist Bypass)
        is_whitelisted = client_ip in WHITELIST_IPS
        
        if not is_whitelisted:
            lock_data = conn.execute('SELECT * FROM lockouts WHERE ip=?', (client_ip,)).fetchone()
            attempts, lockout = (lock_data['attempts'], lock_data['lockout_until']) if lock_data else (0, 0)
            if now < lockout: raise HTTPException(status_code=429, detail="IP_LOCKED")

        if not secrets.compare_digest(x_admin_key or "", ADMIN_KEY):
            if not is_whitelisted:
                attempts += 1
                new_lockout = now + 600 if attempts >= 3 else 0
                conn.execute('INSERT OR REPLACE INTO lockouts VALUES (?, ?, ?)', (client_ip, attempts, new_lockout))
            raise HTTPException(status_code=401, detail="AUTH_DENIED")

        # 2. ATOMIC DOUBLE-SPEND FIX
        cursor = conn.execute('UPDATE pending SET status="APPROVED" WHERE id=? AND status="WAITING"', (req_id,))
        if cursor.rowcount == 0 or choice != "allow":
            raise HTTPException(status_code=400, detail="STALE_OR_DENIED")

        # 3. SETTLE FUNDS (With Version-aware parsing)
        txn = conn.execute('SELECT request_json, version FROM pending WHERE id=?', (req_id,)).fetchone()
        r = json.loads(txn['request_json'])
        
        # In the future, you can check txn['version'] to handle different data shapes
        bank = UAIPFinancialEngine()
        bank.process_settlement(r['sender_id'], Decimal(r['amount']), "provider_01", r['chain'])
        
        conn.execute('UPDATE action_logs SET decision="HUMAN_APPROVED" WHERE id=?', (req_id,))
        if not is_whitelisted: conn.execute('DELETE FROM lockouts WHERE ip=?', (client_ip,))

    return {"status": "SETTLED"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with db_session() as conn:
        logs_data = conn.execute('SELECT * FROM action_logs ORDER BY ts DESC LIMIT 15').fetchall()

    rows = "".join([f"<tr><td>{l['sender']}</td><td>{l['task']}</td><td>${l['amount']}</td><td style='color:{'green' if l['decision']=='ALLOW' else 'orange'}'>{l['decision']}</td><td><button onclick=\"auth('{l['id']}')\">Approve</button></td></tr>" for l in logs_data])
    
    return f"""
    <html>
        <head><meta http-equiv='refresh' content='5'><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:40px;}} table{{width:100%;background:#161b22;}} td{{padding:12px;border-bottom:1px solid #333;}} button{{background:#238636;color:white;border:none;padding:8px;cursor:pointer;border-radius:4px;}}</style></head>
        <body>
            <h1>🛡️ UAIP Master Command Center (v3.0)</h1>
            <p>Admin Whitelist: {'Active' if len(WHITELIST_IPS)>0 else 'None'} | Protocol: {UAIP_PROTOCOL_VERSION}</p>
            <table><thead><tr><th>DID</th><th>Action</th><th>Value</th><th>Status</th><th>Intervention</th></tr></thead><tbody>{rows}</tbody></table>
            <script>
                async function auth(id) {{
                    const k = prompt('Enter Admin Key:');
                    if(!k) return;
                    const res = await fetch('/v1/decision/'+id+'/allow', {{ method:'POST', headers:{{'X-Admin-Key':k}} }});
                    const d = await res.json();
                    if(d.status === 'SETTLED') {{ alert('✅ Payout Executed'); }}
                    else {{ alert('❌ Rejected: ' + (d.detail || 'Unauthorized')); }}
                    location.reload();
                }}
            </script>
        </body>
    </html>"""

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    with db_session() as conn:
        res = conn.execute('SELECT status FROM pending WHERE id=?', (req_id,)).fetchone()
        return {"status": res['status'] if res else "PENDING"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
