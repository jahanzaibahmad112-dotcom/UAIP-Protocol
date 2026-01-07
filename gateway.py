from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid
import time
import json
from typing import Dict, Any, List

# --- IMPORTING THE UNICORN PILLARS ---
from settlement import MultiChainSettlement
from privacy import ZK_Privacy
# (Note: We assume discovery logic is handled within the gateway state for now)

app = FastAPI(title="UAIP + AgentGuard: Secure Global Gateway")

# --- SYSTEM STATE ---
settlement_engine = MultiChainSettlement()
action_logs = []
pending_approvals = {}
agent_registry = {} # Stores Agent Manifests & Reputation

# --- 1. THE INTELLIGENT POLICY ENGINE (95% Automation) ---
def autonomous_judge(task: str, amount: float, privacy_proof: str = None):
    """
    The Intelligence Layer: Reduces Human intervention to 5%.
    """
    # Rule 1: High Value is an automatic 'Pending'
    if amount > 1000.0:
        return "PENDING", "Financial Threshold Exceeded: Requires Human Authorization."
    
    # Rule 2: Critical Operations
    critical_keywords = ["delete", "admin", "withdraw", "shutdown"]
    if any(word in task.lower() for word in critical_keywords):
        return "PENDING", "Critical System Action detected: Escalating to Commander."
    
    # Rule 3: Privacy Check (ZK-Lite)
    if privacy_proof and len(privacy_proof) < 10:
        return "BLOCK", "Security Breach: Invalid ZK-Privacy Proof provided."

    return "ALLOW", "Auto-approved by AgentGuard SLM Policy."

# --- 2. THE SECURE EXECUTION ROUTE ---
class UAIPRequest(BaseModel):
    sender_id: str
    target_task: str
    amount: float
    chain: str # e.g., "BASE", "SOLANA"
    data: Dict[str, Any]
    zk_proof: str = None # The Zero-Knowledge Proof

@app.post("/v1/execute")
async def execute_transaction(req: UAIPRequest):
    request_id = str(uuid.uuid4())[:8]
    
    # A. GOVERNANCE: Run the Autonomous Judge
    decision, reason = autonomous_judge(req.target_task, req.amount, req.zk_proof)
    
    # B. LOGGING: Record for the Audit Trail (Enterprise Gold)
    log_entry = {
        "id": request_id,
        "time": time.strftime("%H:%M:%S"),
        "sender": req.sender_id,
        "task": req.target_task,
        "amount": f"{req.amount} ({req.chain})",
        "decision": decision,
        "reason": reason
    }
    action_logs.insert(0, log_entry)

    # C. HANDLING THE DECISION
    if decision == "BLOCK":
        raise HTTPException(status_code=403, detail=reason)

    if decision == "PENDING":
        pending_approvals[request_id] = "WAITING"
        return {
            "status": "PAUSED", 
            "request_id": request_id, 
            "message": "Action held for Human-in-the-Loop approval."
        }

    # D. SETTLEMENT: Lock funds on the Multi-chain rail
    try:
        tx_id = settlement_engine.lock_funds_cross_chain(req.sender_id, req.amount, req.chain)
        return {
            "status": "SUCCESS", 
            "tx_id": tx_id, 
            "message": "Funds settled and task routed via UAIP."
        }
    except Exception as e:
        raise HTTPException(status_code=402, detail=str(e))

# --- 3. THE COMMAND CENTER (DASHBOARD) ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    log_rows = ""
    for log in action_logs:
        color = "green" if "ALLOW" in log['decision'] else "orange" if "PENDING" in log['decision'] else "red"
        
        # Add 'Approve/Deny' buttons only for Pending items
        btns = ""
        if "PENDING" in log['decision']:
            btns = f"""
            <button onclick="decide('{log['id']}', 'allow')" style="background: #238636; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">Approve</button>
            <button onclick="decide('{log['id']}', 'deny')" style="background: #da3633; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">Deny</button>
            """
        
        log_rows += f"""
        <tr style="border-bottom: 1px solid #30363d;">
            <td style="padding: 12px;">{log['time']}</td>
            <td style="padding: 12px;">{log['sender']}</td>
            <td style="padding: 12px;"><code>{log['task']}</code></td>
            <td style="padding: 12px;">{log['amount']}</td>
            <td style="padding: 12px; color: {color}; font-weight: bold;">{log['decision']}</td>
            <td style="padding: 12px;">{log['reason']}</td>
            <td style="padding: 12px;">{btns}</td>
        </tr>
        """

    return f"""
    <html>
        <head>
            <title>UAIP Command Center</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 40px; }}
                .container {{ max-width: 1200px; margin: auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th {{ text-align: left; color: #8b949e; border-bottom: 2px solid #30363d; padding: 12px; }}
                h1 {{ color: #58a6ff; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ UAIP + AgentGuard: Global Command Center</h1>
                <p>Monitoring {len(action_logs)} live agentic transactions across BASE, SOLANA, and ETHEREUM.</p>
                <table>
                    <thead>
                        <tr><th>Time</th><th>Agent</th><th>Task</th><th>Value</th><th>Decision</th><th>Security Reason</th><th>Intervention</th></tr>
                    </thead>
                    <tbody>{log_rows}</tbody>
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

# --- 4. HUMAN-IN-THE-LOOP INTERVENTION ---
@app.post("/v1/decision/{req_id}/{choice}")
async def manual_decision(req_id: str, choice: str):
    if req_id in pending_approvals:
        result = "APPROVED" if choice == "allow" else "DENIED"
        pending_approvals[req_id] = result
        # Update Log
        for log in action_logs:
            if log['id'] == req_id:
                log['decision'] = f"HUMAN_{result}"
        return {"status": "success"}
    return {"status": "error", "message": "Request ID not found"}

@app.get("/v1/check-status/{req_id}")
async def check_status(req_id: str):
    # This is what the SDK polls to see if the human clicked yet
    status = pending_approvals.get(req_id, "APPROVED")
    return {"status": status}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
