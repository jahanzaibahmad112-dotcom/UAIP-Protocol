from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import uvicorn

app = FastAPI(title="UAIP Universal Gateway")

# Simplified In-Memory Registry (In production, use a Database)
registry = {} 

class RegisterRequest(BaseModel):
    agent_id: str
    public_key: str
    manifest: Dict[str, Any]

@app.post("/register")
async def register(data: RegisterRequest):
    registry[data.agent_id] = {
        "public_key": data.public_key,
        "manifest": data.manifest
    }
    return {"status": "success", "message": f"Agent {data.agent_id} is now discoverable."}

@app.get("/discover/{task}")
async def discover(task: str):
    # Find agents that can perform the specific task
    results = []
    for aid, info in registry.items():
        if any(cap['task'] == task for cap in info['manifest']['capabilities']):
            results.append({"agent_id": aid, "endpoint": info['manifest']['endpoint']})
    return results

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)