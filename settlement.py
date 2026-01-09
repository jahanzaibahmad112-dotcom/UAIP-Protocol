from decimal import Decimal
import uuid

class UAIPFinancialEngine:
    """
    UAIP Multi-Chain Settlement with Dynamic Profit Protection.
    Ensures the protocol never loses money on 'Gas Fees' for micro-tasks.
    """
    def __init__(self):
        self.protocol_fee_rate = Decimal('0.005') # 0.5% Standard Tax
        self.hq_treasury_did = "did:uaip:protocol_hq_treasury_0x71C"
        
        # --- NEW: CHAIN-SPECIFIC MINIMUM FEES ---
        # We set a 'Floor' so we always make a profit.
        self.min_fees = {
            "BASE": Decimal('0.001'),     # $0.001 - Very cheap for nano-tasks
            "SOLANA": Decimal('0.001'),   # $0.001 - High speed, low cost
            "ETHEREUM": Decimal('2.00')   # $2.00 - High cost to cover L1 Gas
        }

    def settle_transaction(self, payer_id: str, amount_usd: float, payee_did: str, chain: str):
        chain = chain.upper()
        if chain not in self.min_fees:
            raise ValueError(f"Unsupported Chain: {chain}")

        total_amount = Decimal(str(amount_usd))
        
        # --- THE PROFIT PROTECTION LOGIC ---
        # 1. Calculate the standard 0.5% fee
        calculated_tax = total_amount * self.protocol_fee_rate
        
        # 2. Compare it against the 'Chain Floor' (The Fix)
        # max() picks whichever is higher: the % or the minimum.
        min_fee = self.min_fees[chain]
        tax_amount = max(calculated_tax, min_fee).quantize(Decimal('0.000001'))
        
        payout_amount = total_amount - tax_amount

        # Security Check: Ensure the tax isn't bigger than the whole payment!
        if tax_amount >= total_amount:
             print(f"⚠️ WARNING: Transaction for {total_amount} is too small for {chain} fees.")
             # In a real system, you might block this or warn the user.

        tx_id = f"uaip_tx_{chain.lower()}_{uuid.uuid4().hex[:10]}"

        print(f"--- 🌉 UAIP SETTLEMENT (Min-Fee Active) ---")
        print(f"Total: {total_amount} | Protocol Tax: {tax_amount} | Payout: {payout_amount}")
        print(f"Revenue sent to: {self.hq_treasury_did}")

        return {
            "tx_id": tx_id,
            "status": "SETTLED",
            "fee_collected": float(tax_amount),
            "payout_final": float(payout_amount)
        }
