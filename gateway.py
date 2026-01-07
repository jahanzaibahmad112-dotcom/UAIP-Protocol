from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from decimal import Decimal
import uuid
import time
import json
from typing import Dict, Any, List
import nacl.signing
import nacl.encoding

app = FastAPI(title="UAIP + AgentGuard Unified Gateway")

# --- 1. INTERNAL MODULES (SETTLEMENT & DISCOVERY) ---
class UAIPSystem:
    def __init__(self):
        self.wallets = {}  # {agent_id: Decimal}
        self.escrow = {}   # {contract_id: Decimal}
        self.registry = {} # {agent_id: manifest}
        self.logs = []
        self.pending = {}

    def auto_judge(self, task, amount):
        """The 95% Automation Logic"""
        if amount > 500.0 or "delete" in task.lower() or "admin" in task.lower():
            return "PENDING", "High-Risk: Manual intervention required."
        return "ALLOW", "Auto-approved by Policy Engine."

# Initialize System
sys = UAIPSystem()

# --- 2. THE SECURE ROUTER ---
class TransactionRequest(BaseModel):
    sender_id: str
    task: str
    amount: float
    data: Dict[str, Any]
    public_key: str
    signature: str

@app.post("/v1/execute")
async def execute(req: TransactionRequest):
    # Security: Verify Signature (Military Grade)
    # [Insert crypto verification logic here]
    
    # Intelligence: Decide if we need a human
    decision, reason = sys.auto_judge(req.task, req.amount)
    request_id = str(uuid.uuid4())[:8]
    
    log_entry = {
        "id": request_id, "time": time.strftime("%H:%M:%S"),
        "sender": req.sender_id, "task": req.task, "amount": f"${req.amount}",
        "decision": decision, "reason": reason
    }
    sys.logs.insert(0, log_entry)

    if decision == "PENDING":
        sys.pending[request_id] = "WAITING"
        return {"status": "PAUSED", "request_id": request_id, "message": reason}

    # UAIP Settlement: If allowed, lock funds
    # [Insert Escrow locking logic here]
    
    return {"status": "SUCCESS", "message": "Task routed securely via UAIP."}

# --- 3. THE COMMAND CENTER (DASHBOARD) ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    log_rows = ""
    for log in sys.logs:
        color = "green" if "ALLOW" in log['decision'] else "orange" if "PENDING" in log['decision'] else "red"
        btns = f"<button onclick=\"decide('{log['id']}','allow')\">Approve</button><button onclick=\"decide('{log['id']}','deny')\">Deny</button>" if log['decision'] == "PENDING" else ""
        log_rows += f"<tr><td>{log['time']}</td><td>{log['sender']}</td><td>{log['task']}</td><td>{log['amount']}</td><td style='color:{color}'>{log['decision']}</td><td>{btns}</td></tr>"

    return f"""
    <html>
        <head><style>body{{font-family:sans-serif; background:#0e1117; color:white; padding:20px;}} table{{width:100%; border-collapse:collapse;}} th,td{{padding:10px; border-bottom:1px solid #333;}} button{{margin-right:5px; cursor:pointer;}}</style></head>
        <body>
            <h1>🛡️ UAIP + AgentGuard Command Center</h1>
            <table><thead><tr><th>Time</th><th>Agent</th><th>Task</th><th>Value</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>{log_rows}</tbody></table>
            <script>async function decide(id, val){{ await fetch('/v1/decision/'+id+'/'+val, {{method:'POST'}}); location.reload(); }}</script>
        </body>
    </html>"""

@app.post("/v1/decision/{req_id}/{choice}")
async def make_decision(req_id: str, choice: str):
    if req_id in sys.pending:
        sys.pending[req_id] = "APPROVED" if choice == "allow" else "DENIED"
        for log in sys.logs:
            if log['id'] == req_id: log['decision'] = "HUMAN_" + sys.pending[req_id]
    return {"status": "ok"}

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    return {"status": sys.pending.get(req_id, "APPROVED")}