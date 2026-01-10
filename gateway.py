from fastapi import FastAPI, HTTPException, Header, Request
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

app = FastAPI(title="UAIP Master Gateway")

# --- CONFIGURATION ---
ADMIN_KEY = os.getenv("ADMIN_KEY", "uaip-secret-123")
DB_PATH = "uaip_vault.db"
UAIP_VERSION = "1.0.0"

# --- 2. DATA MODELS ---
class UAIPPacket(BaseModel):
    sender_id: str
    task: str
    amount: str
    chain: str
    intent: str
    data: dict
    signature: str
    public_key: str
    nonce: str
    timestamp: float
    zk_proof: dict

# --- 3. DATABASE ARCHITECTURE ---
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
        # Table with 'law' column for RAG
        c.execute('CREATE TABLE IF NOT EXISTS action_logs (id TEXT PRIMARY KEY, sender TEXT, task TEXT, amount TEXT, decision TEXT, law TEXT, ts REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS blacklist (did TEXT PRIMARY KEY, ts REAL)')

init_db()

# --- 4. MAINTENANCE ---
def cleanup_task():
    while True:
        try:
            with db_session() as conn:
                conn.execute('DELETE FROM nonces WHERE ts < ?', (time.time() - 120,))
                conn.execute('DELETE FROM action_logs WHERE ts < ?', (time.time() - 86400,))
        except: pass
        time.sleep(60)
threading.Thread(target=cleanup_task, daemon=True).start()

# --- 5. ENDPOINTS ---

@app.post("/v1/register")
async def register(req: dict):
    try:
        data, sig, pk = req["registration_data"], req["signature"], req["public_key"]
        vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(sig))
        with db_session() as conn:
            conn.execute('INSERT OR REPLACE INTO inventory VALUES (?, ?, ?)', (data["agent_id"], pk, str(data["zk_commitment"])))
        return {"status": "REGISTERED"}
    except: raise HTTPException(status_code=401)

@app.post("/v1/execute")
async def execute(req: UAIPPacket):
    now = time.time()
    amount_dec = Decimal(req.amount)
    auditor = ComplianceAuditor()

    with db_session() as conn:
        if conn.execute('SELECT did FROM blacklist WHERE did=?', (req.sender_id,)).fetchone():
            raise HTTPException(status_code=403, detail="BLACKLISTED")
        
        try:
            conn.execute('INSERT INTO nonces VALUES (?, ?)', (req.nonce, now))
        except: raise HTTPException(status_code=403, detail="REPLAY")

        try:
            vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
            msg = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vk.verify(msg, bytes.fromhex(req.signature))
            agent = conn.execute('SELECT zk_commitment FROM inventory WHERE did=?', (req.sender_id,)).fetchone()
            if not agent or not ZK_Privacy.verify_proof(req.zk_proof, int(agent['zk_commitment'])): raise Exception()
        except: raise HTTPException(status_code=401, detail="IDENTITY_ERROR")

        # ACTIVE ENFORCER
        audit_status, audit_report = auditor.run_active_audit({"sender": req.sender_id, "task": req.task, "amount": req.amount})
        if audit_status == "TERMINATE":
            conn.execute('INSERT OR REPLACE INTO blacklist VALUES (?, ?)', (req.sender_id, now))
            raise HTTPException(status_code=451)

        decision = "PENDING" if (amount_dec >= 1000 or audit_status == "PENDING_ENFORCED") else "ALLOW"
        if amount_dec < 10 and audit_status != "TERMINATE": decision = "ALLOW"

        req_id = str(uuid.uuid4())[:8]
        conn.execute('INSERT INTO action_logs (id, sender, task, amount, decision, law, ts) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (req_id, html.escape(req.sender_id), html.escape(req.task), str(amount_dec), decision, audit_report['grounded_law'], now))

        if decision == "PENDING":
            conn.execute('INSERT INTO pending (id, status, request_json, version) VALUES (?, ?, ?, ?)', (req_id, "WAITING", req.json(), UAIP_VERSION))
            return {"status": "PAUSED", "request_id": req_id}

        UAIPFinancialEngine().process_settlement(req.sender_id, amount_dec, "provider_01", req.chain)
        return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    try:
        with db_session() as conn:
            logs_data = conn.execute('SELECT * FROM action_logs ORDER BY ts DESC LIMIT 15').fetchall()
        
        for l in logs_data:
            # Defensive check for missing keys
            d_sender = l['sender'] if 'sender' in l.keys() else "Unknown"
            d_task = l['task'] if 'task' in l.keys() else "Unknown"
            d_amount = l['amount'] if 'amount' in l.keys() else "0.0"
            d_decision = l['decision'] if 'decision' in l.keys() else "UNKNOWN"
            d_law = l['law'] if 'law' in l.keys() else "N/A"
            
            color = "green" if d_decision in ["ALLOW", "HUMAN_APPROVED"] else "orange"
            action_ui = f"<button onclick=\"auth('{l['id']}')\">Approve</button>" if d_decision == "PENDING" else "✅ PAID"
            
            rows += f"""
            <tr>
                <td>{d_sender}</td>
                <td>{d_task}</td>
                <td><b>${d_amount}</b></td>
                <td style='color:{color}'>{d_decision}</td>
                <td style='font-size: 0.85em; color: #8b949e;'>{d_law}</td>
                <td>{action_ui}</td>
            </tr>
            """
    except Exception as e:
        rows = f"<tr><td colspan='6'>Database Error: {str(e)}. Please delete uaip_vault.db and restart.</td></tr>"

    return f"""
    <html>
        <head><meta http-equiv='refresh' content='5'><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:40px;}} table{{width:100%;border-collapse:collapse;}} td,th{{padding:12px;border-bottom:1px solid #333;text-align:left;}} button{{background:#238636;color:white;border:none;padding:8px;cursor:pointer;border-radius:4px;}}</style></head>
        <body>
            <h1>🛡️ AgentGuard Master Dashboard</h1>
            <table><thead><tr><th>Agent DID</th><th>Intent</th><th>Value</th><th>Status</th><th>Legal Grounding (RAG)</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table>
            <script>
                async function auth(id) {{
                    const k = prompt('Enter Admin Key:');
                    if(!k) return;
                    const res = await fetch('/v1/decision/'+id+'/allow', {{ method:'POST', headers:{{'X-Admin-Key':k}} }});
                    const d = await res.json();
                    if(d.status === 'SETTLED') {{ alert('✅ Success: Funds Released'); location.reload(); }}
                    else {{ alert('❌ Error: Unauthorized'); }}
                }}
            </script>
        </body>
    </html>"""

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(request: Request, req_id: str, choice: str, x_admin_key: str = Header(None)):
    with db_session() as conn:
        if not secrets.compare_digest(x_admin_key or "", ADMIN_KEY): raise HTTPException(status_code=401)
        cursor = conn.execute('UPDATE pending SET status="APPROVED" WHERE id=? AND status="WAITING"', (req_id,))
        if cursor.rowcount == 0 or choice != "allow": raise HTTPException(status_code=400)
        txn = conn.execute('SELECT request_json FROM pending WHERE id=?', (req_id,)).fetchone()
        r = json.loads(txn['request_json'])
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
