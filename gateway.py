from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json, html, os
import nacl.signing, nacl.encoding
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from privacy import ZK_Privacy

app = FastAPI()
ADMIN_KEY = "uaip-secret-123"
DB_FILE = "uaip_state.json"

# Persistent State Init
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f: json.dump({"inventory": {}, "pending": {}, "nonces": {}}, f)

def access_db(write_data=None):
    if write_data: 
        with open(DB_FILE, "w") as f: json.dump(write_data, f)
    with open(DB_FILE, "r") as f: return json.load(f)

bank, auditor = UAIPFinancialEngine(), ComplianceAuditor()
logs = []

class UAIPPacket(BaseModel):
    sender_id: str; task: str; amount: float; chain: str; intent: str; data: dict
    signature: str; public_key: str; nonce: str; timestamp: float; zk_proof: dict

@app.post("/v1/register")
async def register(req: dict):
    # Deterministic verification of registration
    try:
        data, sig, pk = req["registration_data"], req["signature"], req["public_key"]
        vk = nacl.signing.VerifyKey(pk, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(sig))
        
        db = access_db()
        db["inventory"][data["agent_id"]] = {"zk_commitment": data["zk_commitment"], "public_key": pk}
        access_db(db)
        return {"status": "VERIFIED"}
    except: raise HTTPException(status_code=401)

@app.post("/v1/execute")
async def execute(req: UAIPPacket):
    db = access_db()
    
    # 1. Replay & Expiration Check
    if time.time() - req.timestamp > 60 or req.nonce in db["nonces"]:
        raise HTTPException(status_code=403, detail="REPLAY_OR_EXPIRED")
    db["nonces"][req.nonce] = time.time()

    # 2. Identity & ZK Verification
    try:
        vk = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(req.data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        vk.verify(msg, bytes.fromhex(req.signature))
        
        commitment = db["inventory"].get(req.sender_id, {}).get("zk_commitment")
        if not ZK_Privacy.verify_proof(req.zk_proof, commitment): raise Exception()
    except: raise HTTPException(status_code=401, detail="CRYPTO_FAILURE")

    # 3. Governance & XSS Protection
    decision = "PENDING" if req.amount >= 1000 or any(w in req.task.lower() for w in auditor.risk_keywords) else "ALLOW"
    log_entry = {"id": str(uuid.uuid4())[:8], "sender": html.escape(req.sender_id), "task": html.escape(req.task), "amount": req.amount, "decision": decision, "chain": req.chain}
    logs.insert(0, log_entry)
    auditor.verify_and_audit(log_entry)

    if decision == "PENDING":
        db["pending"][log_entry["id"]] = {"status": "WAITING", "req": req.dict()}
        access_db(db)
        return {"status": "PAUSED", "request_id": log_entry["id"]}

    bank.process_settlement(req.sender_id, req.amount, "provider_0x1", req.chain)
    access_db(db)
    return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = "".join([f"<tr><td>{l['sender']}</td><td>{l['task']}</td><td>{l['amount']}</td><td style='color:{'green' if l['decision']=='ALLOW' else 'orange'}'>{l['decision']}</td><td><button onclick=\"auth('{l['id']}','allow')\">Approve</button></td></tr>" for l in logs])
    return f"<html><head><meta http-equiv='refresh' content='5'><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:40px;}}table{{width:100%;border-collapse:collapse;}}td{{padding:10px;border-bottom:1px solid #333;}}button{{background:#238636;color:white;cursor:pointer; border:none; padding:5px;}}</style></head><body><h1>🛡️ UAIP Master Command Center</h1><table>{rows}</table><script>async def auth(id, val) {{ const k = prompt('Admin Key:'); await fetch('/v1/decision/'+id+'/'+val, {{method:'POST', headers:{{'X-Admin-Key':k}}}}); location.reload(); }}</script></body></html>"

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str, x_admin_key: str = Header(None)):
    if x_admin_key != ADMIN_KEY: raise HTTPException(status_code=401)
    db = access_db()
    if req_id in db["pending"] and choice == "allow":
        r = db["pending"][req_id]["req"]
        bank.process_settlement(r['sender_id'], r['amount'], "provider_01", r['chain'])
        db["pending"][req_id]["status"] = "APPROVED"
        access_db(db)
        return {"status": "SETTLED"}
    return {"status": "DENIED"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    return {"status": access_db()["pending"].get(req_id, {}).get("status", "PENDING")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
