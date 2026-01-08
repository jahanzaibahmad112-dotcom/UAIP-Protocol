from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json
from typing import Dict, Any

app = FastAPI()

# --- THE DATA STORE ---
action_logs = []
pending_approvals = {}

class UAIPRequest(BaseModel):
    sender_id: str
    task: str
    amount: float
    chain: str
    data: Dict[str, Any]

@app.post("/v1/execute")
async def execute_transaction(req: UAIPRequest):
    request_id = str(uuid.uuid4())[:8]
    
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
    print(f"✅ RECEIVED: {req.task} from {req.sender_id}")
    
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
    
    # --- CAREFUL: THIS IS THE PART THAT WAS CUT OFF BEFORE ---
    html_content = f"""
    <html>
        <head>
            <meta http-equiv="refresh" content="2">
            <style>body{{background:#111;color:white;font-family:sans-serif;padding:30px;}}table{{width:100%;border-collapse:collapse;}}th,td{{padding:10px;text-align:left;}}</style>
        </head>
        <body>
            <h1>🛡️ UAIP + AgentGuard Live Dashboard</h1>
            <table>
                <thead><tr><th>Time</th><th>Agent</th><th>Task</th><th>Value</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
            <script>
                async function decide(id, val) {{
                    await fetch('/v1/decision/' + id + '/' + val, {{method: 'POST'}});
                    location.reload();
                }}
            </script>
        </body>
    </html>
    """
    return html_content

@app.post("/v1/decision/{req_id}/{choice}")
async def decision(req_id: str, choice: str):
    res = "APPROVED" if choice == "allow" else "DENIED"
    pending_approvals[req_id] = res
    for l in action_logs:
        if l['id'] == req_id:
            l['decision'] = f"HUMAN_{res}"
    return {"status": "ok"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    return {"status": pending_approvals.get(req_id, "APPROVED")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
