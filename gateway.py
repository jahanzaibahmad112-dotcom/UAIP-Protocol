from fastapi import FastAPI, HTTPException
from discovery import GlobalDiscoveryService
from translation import SemanticTranslator
from settlement import UAIPEscrow
from security import UAIPSecurity

app = FastAPI(title="UAIP Universal Gateway")

# Initialize the Pillars
gds = GlobalDiscoveryService()
ste = SemanticTranslator()
escrow = UAIPEscrow()

@app.post("/route_task")
async def route_task(sender_id: str, task: str, data: Dict, signature: str, public_key: str):
    # 1. Verify Identity
    if not UAIPSecurity.verify_packet(data, signature, public_key):
        raise HTTPException(status_code=403, detail="Invalid Signature")

    # 2. Discovery: Find the best agent
    providers = gds.search(task)
    if not providers:
        raise HTTPException(status_code=404, detail="No capable agents found")
    
    best_provider = providers[0]

    # 3. Translation: Make the data compatible
    # (Assume we fetch target_schema from the provider's manifest)
    target_schema = {"user_email": "string", "amount_cents": "int"} 
    ready_data = ste.translate_payload(data, target_schema)

    # 4. Settlement: Lock funds
    contract_id = escrow.lock_funds(sender_id, best_provider['price'])

    return {
        "status": "Ready to Execute",
        "contract_id": contract_id,
        "provider_endpoint": best_provider['endpoint'],
        "translated_payload": ready_data
    }
