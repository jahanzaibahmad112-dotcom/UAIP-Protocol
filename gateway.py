from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid
import time
from typing import Dict, Any, List

# --- PILLARS ---
from settlement import MultiChainSettlement
from privacy import ZK_Privacy

app = FastAPI(title="UAIP + AgentGuard Unified Gateway")

# --- STATE ---
settlement_engine = MultiChainSettlement()
action_logs = []  # THIS STORES THE DATA
pending_approvals = {}

def autonomous_judge(task: str, amount: float):
    if amount > 1000.0 or any(word in task.lower() for word in ["delete", "withdraw"]):
        return "PENDING", "High-Risk Action Detected."
    return "ALLOW", "Auto-approved by Policy."

class UAIPRequest(BaseModel):
    sender_id: str
    target_task: str
    amount: float
    chain: str
    data: Dict[str, Any]
    zk_proof: str = None

@app.post("/v1/execute")
async def execute_transaction(req: UAIPRequest):
    request_id = str(uuid.uuid4())[:8]
    decision, reason = autonomous_judge(req.target_task, req.amount)
    
    log_entry = {
        "id": request_id,
        "time": time.strftime("%H:%M:%S"),
        "sender": req.sender_id,
        "task": req.target_task,
        "amount": f"{req.amount} ({req.chain})",
        "decision": decision,
        "reason": reason
    }
    
    # CRITICAL FIX: Add to the list and print to terminal for debugging
    action_logs.insert(0, log_entry)
    print(f"✔️ LOG ADDED: {req.target_task} from {req.sender_id}")

    if decision == "PENDING":
        pending_approvals[request_id] = "WAITING"
        return {"status": "PAUSED", "request_id": request_id, "message": reason}

    return {"status": "SUCCESS", "message": "Routed."}

# --- UPDATED DASHBOARD WITH AUTO-REFRESH ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    log_rows = ""
    for log in action_logs:
        color = "green" if "ALLOW" in log['decision'] else "orange" if "PENDING" in log['decision'] else "red"
        btns = f"<button onclick=\"decide('{log['id']}','allow')\" style='background:green;color:white;border:none;padding:5px;cursor:pointer;'>Approve</button>" if log['decision'] == "PENDING" else ""
        
        log_rows += f"""
        <tr style="border-bottom: 1px solid #333;">
            <td style="padding:10px;">{log['time']}</td>
            <td style="padding:10px;">{log['sender']}</td>
            <td style="padding:10px;">{log['task']}</td>
            <td style="padding:10px; color:{color}; font-weight:bold;">{log['decision']}</td>
            <td style="padding:10px;">{btns}</td>
        </tr>
        """

    return f"""
    <html>
        <head>
            <title>UAIP Command Center</title>
            <!-- REFRESH EVERY 3 SECONDS -->
            <meta http-equiv="refresh" content="3">
            <style>
                body {{ font-family: sans-serif; background: #0d1117; color: white; padding: 40px; }}
                table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; }}
                th {{ text-align: left; padding: 15px; border-bottom: 2px solid #30363d; color: #8b949e; }}
            </style>
        </head>
        <body>
            <h1>🛡️ UAIP + AgentGuard: Live Command Center</h1>
            <table>
                <thead><tr><th>Time</th><th>Agent</th><th>Task</th><th>Status</th><th>Intervention</th></tr></thead>
                <tbody>{log_rows}</tbody>
            </table>
            <script>
                async function decide(id, choice) {{
                    await fetch('/v1/decision/' + id + '/' + choice, {{method: 'POST'}});
                    window.location.reload();
                }}
            </script>
        </body>
    </html>
    """

@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str):
    if req_id in pending_approvals:
        result = "APPROVED" if choice == "allow" else "DENIED"
        pending_approvals[req_id] = result
        for log in action_logs:
            if log['id'] == req_id: log['decision'] = f"HUMAN_{result}"
        return {"status": "success"}

@app.get("/v1/check-status/{req_id}")
async def check_status(req_id: str):
    return {"status": pending_approvals.get(req_id, "APPROVED")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
