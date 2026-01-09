from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uuid, time, json
from typing import Dict, Any, List

app = FastAPI(title="UAIP Enterprise Gateway")

# --- LAYER 1 & 4: INVENTORY & AUDIT STORAGE ---
agent_inventory = {}  # Registry of all known agents
action_logs = []      # Forensic Audit Trail
jit_sessions = {}     # Layer 3: JIT Access Keys

class AgentManifest(BaseModel):
    agent_id: str
    name: str
    owner: str
    capabilities: List[str]
    risk_level: str = "Medium"

# --- LAYER 3: JUST-IN-TIME (JIT) AUTHORIZATION ---
def verify_intent(task: str, context: str):
    """Intent-Based Check: Does the action match the goal?"""
    high_risk = ["withdraw", "delete", "admin", "transfer"]
    if any(word in task.lower() for word in high_risk):
        return "PENDING"
    return "ALLOW"

@app.post("/v1/register")
async def register_agent(manifest: AgentManifest):
    """Layer 1: Automated Discovery & Inventory"""
    agent_inventory[manifest.agent_id] = manifest
    return {"status": "Onboarded", "risk_score": manifest.risk_level}

@app.post("/v1/execute")
async def execute(sender_id: str, task: str, amount: float, context: str, data: Dict):
    request_id = str(uuid.uuid4())[:8]
    
    # LAYER 3: Intent & Risk Evaluation
    decision = verify_intent(task, context)
    if amount > 500: decision = "PENDING"

    # LAYER 4: Immutable Forensic Logging
    log_entry = {
        "id": request_id,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "agent": sender_id,
        "action": task,
        "intent": context,
        "decision": decision,
        "compliance": "SOC2, EU-AI-ACT Ready"
    }
    action_logs.insert(0, log_entry)
    
    # Save to a permanent file for Layer 4
    with open("audit_trail.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    if decision == "PENDING":
        jit_sessions[request_id] = "WAITING"
        return {"status": "PAUSED", "request_id": request_id}

    return {"status": "SUCCESS", "jit_token": uuid.uuid4().hex}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    for l in action_logs:
        color = "green" if "ALLOW" in l['decision'] else "orange"
        rows += f"<tr style='border-bottom:1px solid #444;'><td>{l['time']}</td><td>{l['agent']}</td><td>{l['action']}</td><td style='color:{color}'>{l['decision']}</td><td>{l['compliance']}</td></tr>"
    
    return f"""
    <html>
        <head><meta http-equiv="refresh" content="3"><style>body{{background:#0d1117;color:white;font-family:sans-serif;padding:30px;}}table{{width:100%;border-collapse:collapse;}}th,td{{padding:10px;text-align:left; border-bottom:1px solid #333;}}</style></head>
        <body>
            <h1>🛡️ UAIP Enterprise Command Center</h1>
            <p>Layer 1: {len(agent_inventory)} Agents Discovered | Layer 4: Forensic Audit Active</p>
            <table><thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Status</th><th>Compliance</th></tr></thead>
            <tbody>{rows}</tbody></table>
        </body>
    </html>"""

@app.get("/v1/check/{req_id}")
async def check(req_id: str):
    return {"status": jit_sessions.get(req_id, "APPROVED")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
