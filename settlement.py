from decimal import Decimal
import uuid

class UAIPFinancialEngine:
    """
    3-Tiered Revenue Model:
    Tier A (<$10): $0.01 flat fee.
    Tier B ($10-$10k): 1.0% tax.
    Tier C (>$10k): $10 flat + 0.5% tax.
    """
    def __init__(self):
        self.hq_treasury = "did:uaip:protocol_hq_treasury"
        self.tiers = {
            "NANO_FLAT": Decimal('0.01'),
            "MID_RATE": Decimal('0.01'),
            "ENT_RATE": Decimal('0.005'),
            "ENT_FLAT": Decimal('10.0')
        }

    def calculate_fee(self, amount: Decimal):
        if amount <= 10: return self.tiers["NANO_FLAT"]
        if amount <= 10000: return amount * self.tiers["MID_RATE"]
        return (amount * self.tiers["ENT_RATE"]) + self.tiers["ENT_FLAT"]

    def process_settlement(self, payer_did, amount_usd, payee_did, chain):
        total = Decimal(str(amount_usd))
        fee = self.calculate_fee(total).quantize(Decimal('0.000001'))
        payout = total - fee

        tx_id = f"uaip_tx_{uuid.uuid4().hex[:10]}"
        print(f"🌉 SETTLED: {payout} USDC to {payee_did} | FEE: {fee} USDC to HQ")
        
        return {"tx_id": tx_id, "fee": float(fee), "payout": float(payout)}
