from decimal import Decimal
import uuid

class UAIPFinancialEngine:
    """
    UAIP Multi-Chain Settlement & Revenue Module.
    Implements a 3-Tiered Profit Model optimized for 2026 Agentic Commerce.
    """
    def __init__(self):
        self.hq_treasury_did = "did:uaip:protocol_hq_treasury_0x71C"
        
        # --- NEW PROFIT TIERS ---
        self.nano_flat_fee = Decimal('0.01')      # Tier A: $0.01 flat
        self.mid_tax_rate = Decimal('0.01')       # Tier B: 1.0% 
        self.enterprise_tax_rate = Decimal('0.005') # Tier C: 0.5%
        self.governance_flat_fee = Decimal('10.0')  # Tier C: $10.00 flat
        
    def calculate_protocol_revenue(self, amount: Decimal):
        """Logic for the 3-Tiered Profit Strategy"""
        # Tier A: Nano-Tasks ($0.01 to $10.00)
        if amount <= 10:
            return self.nano_flat_fee
            
        # Tier B: Secure B2B ($10.01 to $10,000.00)
        if amount <= 10000:
            return amount * self.mid_tax_rate
            
        # Tier C: Enterprise Whale (> $10,000.00)
        return (amount * self.enterprise_tax_rate) + self.governance_flat_fee

    def settle_transaction(self, payer_id: str, amount_usd: float, payee_did: str, chain: str):
        total_amount = Decimal(str(amount_usd))
        
        # 1. Execute Tiered Fee Calculation
        tax_amount = self.calculate_protocol_revenue(total_amount).quantize(Decimal('0.000001'))
        payout_amount = total_amount - tax_amount

        # Security Check: Prevent 'Negative Payouts' on extremely small errors
        if payout_amount < 0: payout_amount = Decimal('0.00')

        tx_id = f"uaip_tx_{chain.lower()}_{uuid.uuid4().hex[:10]}"

        print(f"--- 🌉 TIERED SETTLEMENT ACTIVE ---")
        print(f"Amount: ${total_amount} | Tier Revenue: ${tax_amount} | Agent Payout: ${payout_amount}")
        
        return {
            "tx_id": tx_id,
            "status": "SETTLED",
            "fee_collected": float(tax_amount),
            "payout_final": float(payout_amount)
        }
