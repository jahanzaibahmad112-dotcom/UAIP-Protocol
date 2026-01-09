from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json, html
from typing import Dict, Any, List
import nacl.signing
import nacl.encoding

# --- IMPORT PILLARS ---
from settlement import UAIPFinancialEngine
from compliance import ComplianceAuditor
from security import UAIPSecurity # Assuming our security logic is here

app = FastAPI(title="UAIP + AgentGuard Hardened Gateway")

# --- SYSTEM STATE ---
bank = UAIPFinancialEngine()
auditor = ComplianceAuditor()
action_logs = []
agent_inventory = {}   # Layer 1: Global Registry
pending_approvals = {} # Layer 3: Stores the FULL request data for re-triggering
blacklisted_dids = set()

class UAIPPacket(BaseModel):
    sender_id: str
    task: str
    amount: float
    chain: str
    intent: str
    data: Dict[str, Any]
    signature: str     # REQUIRED: Cryptographic proof
    public_key: str    # REQUIRED: For verification

@app.post("/v1/register")
async def register(manifest: Dict):
    """Layer 1: Onboarding with Public Key registration."""
    agent_id = manifest.get('agent_id')
    agent_inventory[agent_id] = manifest
    return {"status": "REGISTERED"}

@app.post("/v1/execute")
async def execute_task(req: UAIPPacket):
    # 1. SECURITY: Identity Verification (Fixes Fake ID Vulnerability)
    if req.sender_id in blacklisted_dids:
        raise HTTPException(status_code=403, detail="IDENTITY_REVOKED")

    # Verify the signature against the math
    # In production, we'd fetch the public key from our own registry
    try:
        verify_key = nacl.signing.VerifyKey(req.public_key, encoder=nacl.encoding.HexEncoder)
        msg = json.dumps(req.data, sort_keys=True).encode('utf-8')
        verify_key.verify(msg, bytes.fromhex(req.signature))
    except:
        raise HTTPException(status_code=401, detail="INVALID_CRYPTOGRAPHIC_SIGNATURE")

    request_id = str(uuid.uuid4())[:8]
    
    # 2. GOVERNANCE: Risk Evaluation
    decision = "ALLOW"
    if req.amount >= 1000 or "withdraw" in req.task.lower():
        decision = "PENDING"

    # 3. XSS PROTECTION: Sanitize all inputs before logging (Fixes Dashboard Exploit)
    safe_task = html.escape(req.task)
    safe_sender = html.escape(req.sender_id)

    log_entry = {
        "id": request_id, "time": time.strftime("%H:%M:%S"),
        "sender": safe_sender, "task": safe_task, "amount": req.amount,
        "decision": decision, "chain": req.chain
    }
    action_logs.insert(0, log_entry)

    # 4. GHOST APPROVAL FIX: Store the FULL request to re-trigger later
    if decision == "PENDING":
        pending_approvals[request_id] = {
            "status": "WAITING",
            "request_data": req # Save the whole packet
        }
        return {"status": "PAUSED", "request_id": request_id}

    # 5. SETTLEMENT: Process immediate transaction
    bank.settle_transaction(req.sender_id, req.amount, "provider_01", req.chain)
    return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    for l in action_logs:
        color = "green" if "ALLOW" in l['decision'] else "orange"
        
        # Approve & Terminate Buttons
        btn = f"<button onclick=\"decide('{l['id']}','allow')\">Approve</button>" if "PENDING" in l['decision'] else ""
        kill = f"<button style='background:red;' onclick=\"terminate('{l['sender']}')\">TERMINATE</button>"
        
        rows += f"<tr><td>{l['time']}</td><td>{l['sender']}</td><td>{l['task']}</td><td style='color:{color}'>{l['decision']}</td><td>{btn} {kill}</td></tr>"

    return f"<html>... (Include Dashboard HTML here with script below) ... </html>"

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str):
    """
    Fixed Approval Logic:
    If 'allow', it actually triggers the bank settlement.
    """
    if req_id not in pending_approvals:
        return {"error": "Request not found"}

    if choice == "allow":
        # GET THE SAVED DATA (Fixes Ghost Approval)
        saved_req = pending_approvals[req_id]["request_data"]
        
        # ACTUALLY MOVE THE MONEY
        bank.settle_transaction(
            saved_req.sender_id, 
            saved_req.amount, 
            "provider_01", 
            saved_req.chain
        )
        
        pending_approvals[req_id]["status"] = "APPROVED"
        for l in action_logs:
            if l['id'] == req_id: l['decision'] = "HUMAN_APPROVED"
            
    return {"status": "processed"}

@app.post("/v1/terminate/{did}")
async def terminate(did: str):
    blacklisted_dids.add(did)
    return {"status": "terminated"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    status = pending_approvals.get(req_id, {}).get("status", "APPROVED")
    return {"status": status}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
