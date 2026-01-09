from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json
from typing import Dict, Any, List

# Import Pillars
from settlement import SettlementEngine
from compliance import ComplianceAuditor

app = FastAPI(title="UAIP + AgentGuard Unified Gateway")

# System State
bank = SettlementEngine()
auditor = ComplianceAuditor()
action_logs = []
agent_inventory = {} # Layer 1: Inventory
pending_approvals = {} # Layer 3: JIT Sessions
blacklisted_dids = set()

class UAIPPacket(BaseModel):
    sender_id: str
    task: str
    amount: float
    chain: str
    intent: str
    data: Dict[str, Any]

@app.post("/v1/register")
async def register(manifest: Dict):
    agent_inventory[manifest['agent_id']] = manifest
    return {"status": "DISCOVERED", "risk": "Medium"}

@app.post("/v1/execute")
async def execute_task(req: UAIPPacket):
    if req.sender_id in blacklisted_dids:
        raise HTTPException(status_code=403, detail="AGENT TERMINATED: Identity Revoked.")

    req_id = str(uuid.uuid4())[:8]
    
    # Layer 3: Autonomous Judge (Intent Check)
    decision = "ALLOW"
    reason = "Verified by AI Judge"
    if req.amount > 1000 or "withdraw" in req.task.lower():
        decision = "PENDING"
        reason = "JIT Elevation Required (High Risk)"

    # Layer 4: Forensic Logging
    log_entry = {
        "id": req_id, "time": time.strftime("%H:%M:%S"),
        "sender": req.sender_id, "task": req.task, "amount": req.amount,
        "decision": decision, "reason": reason, "risk": "High" if req.amount > 500 else "Low"
    }
    action_logs.insert(0, log_entry)

    if decision == "PENDING":
        pending_approvals[req_id] = "WAITING"
        return {"status": "PAUSED", "request_id": req_id, "message": reason}

    # Layer 2: Settlement & 0.5% Fee
    bank.process_transaction(req.sender_id, req.amount, "target_provider", req.chain)
    
    return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    for l in action_logs:
        company = "Microsoft" if "microsoft" in l['sender'] else "OpenAI"
        color = "green" if "ALLOW" in l['decision'] else "orange"
        
        # TERMINATE & APPROVE BUTTONS
        btn = f"<button onclick=\"decide('{l['id']}','allow')\">Approve</button>" if l['decision']=="PENDING" else ""
        kill = f"<button style='background:red;' onclick=\"terminate('{l['sender']}')\">TERMINATE</button>"
        
        rows += f"<tr style='border-bottom:1px solid #333;'><td>{l['time']}</td><td>{company}</td><td>{l['task']}</td><td style='color:{color}'>{l['decision']}</td><td>{btn} {kill}</td></tr>"

    return f"""
    <html>
        <head><meta http-equiv="refresh" content="3"><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:30px;}}table{{width:100%;border-collapse:collapse;}}th,td{{padding:10px;text-align:left;}}button{{color:white;background:#238636;border:none;padding:5px;cursor:pointer;}}</style></head>
        <body>
            <h1>🛡️ UAIP + AgentGuard Command Center</h1>
            <table><thead><tr><th>Time</th><th>Company</th><th>Task</th><th>Status</th><th>Intervention</th></tr></thead>
            <tbody>{rows}</tbody></table>
            <script>
                async function decide(id,val){{ await fetch('/v1/decision/'+id+'/'+val, {{method:'POST'}}); location.reload(); }}
                async function terminate(did){{ await fetch('/v1/terminate/'+did, {{method:'POST'}}); alert('Agent Revoked'); location.reload(); }}
            </script>
        </body>
    </html>"""

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str):
    res = "APPROVED" if choice == "allow" else "DENIED"
    pending_approvals[req_id] = res
    for l in action_logs:
        if l['id'] == req_id: l['decision'] = f"HUMAN_{res}"
    return {"status": "ok"}

@app.post("/v1/terminate/{did}")
async def terminate(did: str):
    blacklisted_dids.add(did)
    return {"status": "terminated"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    return {"status": pending_approvals.get(req_id, "APPROVED")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
