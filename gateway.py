from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json
from typing import Dict, Any

app = FastAPI()

# --- THE VAULT (Where data lives) ---
action_logs = []
pending_approvals = {}

class UAIPRequest(BaseModel):
    sender_id: str
    task: str # Matches the SDK exactly now
    amount: float
    chain: str
    data: Dict[str, Any]

@app.post("/v1/execute")
async def execute_transaction(req: UAIPRequest):
    request_id = str(uuid.uuid4())[:8]
    
    # Simple Rule: Over $1000 needs human
    decision = "ALLOW"
    reason = "Auto-approved"
    if req.amount > 1000:
        decision = "PENDING"
        reason = "High Value - Human Approval Required"
        pending_approvals[request_id] = "WAITING"

    log_entry = {
        "id": request_id,
        "time": time.strftime("%H:%M:%S"),
        "sender": req.sender_id,
        "task": req.task,
        "amount": f"${req.amount} ({req.chain})",
        "decision": decision,
        "reason": reason
    }
    
    action_logs.insert(0, log_entry)
    print(f"✅ RECEIVED: {req.task} from {req.sender_id}") # This shows in your terminal
    
    if decision == "PENDING":
        return {"status": "PAUSED", "request_id": request_id, "message": reason}
    return {"status": "SUCCESS"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    for l in action_logs:
        c = "green" if "ALLOW" in l['decision'] else "orange"
        btn = f"<button onclick=\"decide('{l['id']}','allow')\">Approve</button>" if l['decision']=="PENDING" else ""
        rows += f"<tr style='border-bottom:1px solid #444;'><td>{l['time']}</td><td>{l['sender']}</td><td>{l['task']}</td><td>{l['amount']}</td><td style='color:{c}'>{l['decision']}</td><td>{btn}</td></tr>"
    
    return f"""
    <html>
        <head><meta http-equiv="refresh" content="2"><style>body{{background:#111;color:white;font-family:sans-serif;padding:30px;}}table{{width:100%;border-collapse:collapse;}}th,td{{padding:10px;text-align:left;}}</style></head>
        <body>
            <h1>🛡️ UAIP + AgentGuard Live Dashboard</h1>
            <table><thead><tr><th>Time</th><th>Agent<
