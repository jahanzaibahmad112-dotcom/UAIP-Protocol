from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from decimal import Decimal
from contextlib import contextmanager
import uuid, time, json, html, os, sqlite3, threading, secrets
import nacl.signing, nacl.encoding

from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

app = FastAPI(title="UAIP Master Gateway")
ADMIN_KEY = os.getenv("ADMIN_KEY", "uaip-secret-123")
DB_PATH = "uaip_vault.db"

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
        c.execute('CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, status TEXT, request_json TEXT, audit_json TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS lockouts (ip TEXT PRIMARY KEY, attempts INTEGER, lockout_until REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS action_logs (id TEXT PRIMARY KEY, sender TEXT, task TEXT, amount TEXT, decision TEXT, law TEXT, ts REAL)')

init_db()

@app.post("/v1/register")
async def register(req: dict):
    try:
        data, sig, pk = req["registration_data"], req["signature"], req["public_key"]
        vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(sig))
        with db_session() as conn:
            conn.execute('INSERT OR REPLACE INTO inventory VALUES (?, ?, ?)', (data["agent_id"], pk, str(data["zk_commitment"])))
        return {"status": "IDENTITY_VERIFIED"}
    except: raise HTTPException(status_code=401)

@app.post("/v1/execute")
async def execute(req: UAIPPacket):
    now = time.time()
    amount_dec = Decimal(req.amount)
    auditor = ComplianceAuditor()

    with db_session() as conn:
        # 1. Security Logic
        try:
            conn.execute('INSERT INTO nonces VALUES (?, ?)', (req.nonce, now))
        except: raise HTTPException(status_code=403, detail="REPLAY")

        # 2. Compliance Logic (Active Enforcer)
        audit_status, audit_report = auditor.run_active_audit({"sender": req.sender_id, "task": req.task, "amount": req.amount})
        
        # FIXED: Nano-tasks (<$10) are now AUTO-ALLOWED unless Critical
        decision = "PENDING" if (amount_dec >= 10 or audit_status == "PENDING_ENFORCED") else "ALLOW"
        if audit_status == "TERMINATE": raise HTTPException(status_code=451)

        req_id = str(uuid.uuid4())[:8]
        # Log to DB with Legal Grounding
        conn.execute('INSERT INTO action_logs VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (req_id, html.escape(req.sender_id), html.escape(req.task), str(amount_dec), decision, audit_report['grounded_law'], now))

        if decision == "PENDING":
            conn.execute('INSERT INTO pending VALUES (?, ?, ?, ?)', (req_id, "WAITING", req.json(), json.dumps(audit_report)))
            return {"status": "PAUSED", "request_id": req_id}

        # Immediate Settlement
        UAIPFinancialEngine().process_settlement(req.sender_id, amount_dec, "provider_01", req.chain)
        return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with db_session() as conn:
        logs_data = conn.execute('SELECT * FROM action_logs ORDER BY ts DESC LIMIT 15').fetchall()

    rows = ""
    for l in logs_data:
        color = "green" if l['decision'] in ["ALLOW", "HUMAN_APPROVED"] else "orange"
        # FIXED: Button only shows if status is PENDING
        action_ui = f"<button onclick=\"auth('{l['id']}')\">Approve</button>" if l['decision'] == "PENDING" else "✅ PAID"
        
        rows += f"""
        <tr>
            <td>{l['sender']}</td>
            <td>{l['task']}</td>
            <td><b>${l['amount']}</b></td>
            <td style='color:{color}'>{l['decision']}</td>
            <td style='font-size: 0.8em; color: gray;'>{l['law']}</td>
            <td>{action_ui}</td>
        </tr>
        """
    
    return f"""
    <html>
        <head><meta http-equiv='refresh' content='5'><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:40px;}} table{{width:100%;border-collapse:collapse;}} td,th{{padding:12px;border-bottom:1px solid #333;text-align:left;}} button{{background:#238636;color:white;border:none;padding:8px;cursor:pointer;border-radius:4px;}}</style></head>
        <body>
            <h1>🛡️ AgentGuard Secure Command Center</h1>
            <p>Status: Llama-3-Legal RAG Active | Nano-Task Auto-Approval Enabled (< $10)</p>
            <table><thead><tr><th>Agent DID</th><th>Intent</th><th>Value</th><th>Status</th><th>Legal Grounding (RAG)</th><th>Intervention</th></tr></thead><tbody>{rows}</tbody></table>
            <script>
                async function auth(id) {{
                    const k = prompt('Enter Admin Key:');
                    if(!k) return;
                    const res = await fetch('/v1/decision/'+id+'/allow', {{ method:'POST', headers:{{'X-Admin-Key':k}} }});
                    const d = await res.json();
                    if(d.status === 'SETTLED') {{ alert('✅ Payment Executed Successfully'); location.reload(); }}
                    else {{ alert('❌ Error: Unauthorized'); }}
                }}
            </script>
        </body>
    </html>"""

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(request: Request, req_id: str, choice: str, x_admin_key: str = Header(None)):
    with db_session() as conn:
        if not secrets.compare_digest(x_admin_key or "", ADMIN_KEY): raise HTTPException(status_code=401)

        # Atomic check to prevent double-spending
        cursor = conn.execute('UPDATE pending SET status="APPROVED" WHERE id=? AND status="WAITING"', (req_id,))
        if cursor.rowcount == 0: raise HTTPException(status_code=400)

        txn = conn.execute('SELECT request_json FROM pending WHERE id=?', (req_id,)).fetchone()
        r = json.loads(txn['request_json'])
        
        # PROCESS MONEY
        UAIPFinancialEngine().process_settlement(r['sender_id'], Decimal(r['amount']), "provider_01", r['chain'])
        conn.execute('UPDATE action_logs SET decision="HUMAN_APPROVED" WHERE id=?', (req_id,))

    return {"status": "SETTLED"}

# [Include UAIPPacket Model here]
