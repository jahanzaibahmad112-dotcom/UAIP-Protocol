from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid
import time
import json
import os
from typing import Dict, Any, List

# --- THE THREE UNICORN PILLARS ---
from settlement import MultiChainSettlement
from privacy import ZK_Privacy

app = FastAPI(title="UAIP + AgentGuard Unified Gateway")

# --- SYSTEM STATE ---
settlement_engine = MultiChainSettlement()
action_logs = []  # Live dashboard data
pending_approvals = {} # Human-in-the-loop storage
AUDIT_FILE = "uaip_audit_trail.json"

# --- 1. THE PERMANENT AUDIT LOG (Legal Moat) ---
def save_to_audit_trail(entry):
    """Saves every transaction to a permanent file for lawyers/auditors."""
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# --- 2. THE INTELLIGENT POLICY ENGINE (95% Automation) ---
def autonomous_judge(task: str, amount: float, zk_proof: str = None):
    """Determines if an action is safe or needs human approval."""
    
    # Rule 1: Nano-payment limit (Auto-approve everything under $10)
    if amount <= 10.0:
        return "ALLOW", "Nano-transaction: Auto-approved for efficiency."

    # Rule 2: High Value threshold
    if amount > 1000.0:
        return "PENDING", "High-Value Transaction: Escalated for Human Authorization."
    
    # Rule 3: Critical Keyword Detection
    critical_keywords = ["delete", "admin", "withdraw", "shutdown", "root"]
    if any(word in task.lower() for word in critical_keywords):
        return "PENDING", "Critical Action: Potential system risk detected."
    
    # Rule 4: Privacy Validation
    if zk_proof and len(zk_proof) < 10:
        return "BLOCK", "Security Error: Invalid ZK-Privacy Proof."

    return "ALLOW", "Routine task: Verified by UAIP Governance."

# --- 3. THE SECURE EXECUTION ROUTE (UAIP Standard) ---
class UAIPRequest(BaseModel):
    sender_id: str
    task: str
    amount: float
    chain: str # "BASE", "SOLANA", etc.
    data: Dict[str, Any]
    zk_proof: str = None

@app.post("/v1/execute")
async def execute_transaction(req: UAIPRequest):
    request_id = str(uuid.uuid4())[:8]
    
    # A. GOVERNANCE: Evaluate Risk
    decision, reason = autonomous_judge(req.task, req.amount, req.zk_proof)
    
    # B. CREATE LOG ENTRY
    log_entry = {
        "id": request_id,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sender": req.sender_id,
        "task": req.task,
        "amount": f"${req.amount} ({req.chain})",
        "decision": decision,
        "reason": reason
    }
    
    # C. PERSISTENCE: Save for Dashboard and Permanent Audit Trail
    action_logs.insert(0, log_entry)
    save_to_audit_trail(log_entry)
    print(f"📁 AUDIT RECORDED: {req.task} | Decision: {decision}")

    # D. HANDLE DECISION
    if decision == "BLOCK":
        raise HTTPException(status_code=403, detail=reason)

    if decision == "PENDING":
        pending_approvals[request_id] = "WAITING"
        return {"status": "PAUSED", "request_id": request_id, "message": reason}

    # E. SETTLEMENT: Lock funds across the bridge
    try:
        tx_id = settlement_engine.lock_funds_cross_chain(req.sender_id, req.amount, req.chain)
        return {"status": "SUCCESS", "tx_id": tx_id, "message": "Transaction cleared."}
    except Exception as e:
        raise HTTPException(status_code=402, detail=str(e))

# --- 4. THE LIVE COMMAND CENTER (DASHBOARD) ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    rows = ""
    for log in action_logs:
        color = "green" if "ALLOW" in log['decision'] else "orange" if "PENDING" in log['decision'] else "red"
        
        btns = ""
        if "PENDING" in log['decision']:
            btns = f"""
            <button onclick="decide('{log['id']}', 'allow')" style="background:#238636;color:white;border:none;padding:5px 10px;cursor:pointer;border-radius:4px;">Approve</button>
            <button onclick="decide('{log['id']}', 'deny')" style="background:#da3633;color:white;border:none;padding:5px 10px;cursor:pointer;border-radius:4px;">Deny</button>
            """
        
        rows += f"""
        <tr style="border-bottom:1px solid #30363d;">
            <td style="padding:12px;">{log['time']}</td>
            <td style="padding:12px;">{log['sender']}</td>
            <td style="padding:12px;"><code>{log['task']}</code></td>
            <td style="padding:12px;">{log['amount']}</td>
            <td style="padding:12px; color:{color}; font-weight:bold;">{log['decision']}</td>
            <td style="padding:12px;">{btns}</td>
        </tr>
        """

    return f"""
    <html>
        <head>
            <title>UAIP Command Center</title>
            <meta http-equiv="refresh" content="3">
            <style>
                body {{ font-family: sans-serif; background:#0d1117; color:#c9d1d9; padding:40px; }}
                .box {{ max-width:1100px; margin:auto; background:#161b22; border:1px solid #30363d; padding:20px; border-radius:8px; }}
                table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
                th {{ text-align:left; color:#8b949e; border-bottom:2px solid #30363d; padding:12px; }}
                h1 {{ color:#58a6ff; }}
            </style>
        </head>
        <body>
            <div class="box">
                <h1>🛡️ UAIP + AgentGuard: Secure Clearing House</h1>
                <p>Monitoring Nano-payments and Governance across BASE, SOLANA, and ETHEREUM.</p>
                <table>
                    <thead><tr><th>Time</th><th>Agent</th><th>Task</th><th>Value</th><th>Status</th><th>Intervention</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <script>
                async function decide(id, choice) {{
                    await fetch('/v1/decision/' + id + '/' + choice, {{method: 'POST'}});
                    window.location.reload();
                }}
            </script>
        </body>
    </html>
    """

# --- 5. HUMAN INTERVENTION & POLLING ---
@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str):
    if req_id in pending_approvals:
        res = "APPROVED" if choice == "allow" else "DENIED"
        pending_approvals[req_id] = res
        for log in action_logs:
            if log['id'] == req_id: log['decision'] = f"HUMAN_{res}"
        return {"status": "success"}

@app.get("/v1/check-status/{req_id}")
async def check_status(req_id: str):
    return {"status": pending_approvals.get(req_id, "APPROVED")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
