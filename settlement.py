from decimal import Decimal
import uuid
import time

class MultiChainSettlement:
    """
    The UAIP Multi-chain Settlement Engine.
    Handles high-precision payments across different blockchain rails.
    """
    
    def __init__(self):
        # Supported chains for the 2026 AI Economy
        self.supported_chains = ["BASE", "SOLANA", "ETHEREUM"]
        
        # Internal ledgers
        self.wallets = {}      # {agent_id: {"chain": "BASE", "balance": Decimal}}
        self.escrow_vault = {} # {contract_id: {"amount": Decimal, "target_chain": str}}

    def create_wallet(self, agent_id, chain="BASE", initial_funds=0.0):
        if chain not in self.supported_chains:
            raise ValueError(f"Unsupported chain. Choose from: {self.supported_chains}")
        
        self.wallets[agent_id] = {
            "chain": chain,
            "balance": Decimal(str(initial_funds))
        }
        return True

    def lock_funds_cross_chain(self, payer_id, amount, target_chain):
        """
        Locks funds and prepares for cross-chain bridging if necessary.
        """
        amount_dec = Decimal(str(amount))
        
        if payer_id not in self.wallets or self.wallets[payer_id]["balance"] < amount_dec:
            raise ValueError("Insufficient funds on source chain.")

        # Simulate a Bridge if chains are different
        source_chain = self.wallets[payer_id]["chain"]
        if source_chain != target_chain:
            print(f"🌉 BRIDGE: Initiating transfer from {source_chain} to {target_chain}...")

        contract_id = f"tx_{uuid.uuid4().hex[:8]}"
        
        # Move funds from wallet to escrow
        self.wallets[payer_id]["balance"] -= amount_dec
        self.escrow_vault[contract_id] = {
            "amount": amount_dec,
            "target_chain": target_chain,
            "payer": payer_id,
            "timestamp": time.time()
        }
        
        return contract_id

    def release_funds(self, contract_id, payee_id):
        """Finalizes payment to the provider agent."""
        if contract_id not in self.escrow_vault:
            return False
            
        data = self.escrow_vault.pop(contract_id)
        
        # Ensure payee has a wallet on the target chain
        if payee_id not in self.wallets:
            self.create_wallet(payee_id, chain=data["target_chain"])
            
        self.wallets[payee_id]["balance"] += data["amount"]
        print(f"💰 PAID: {data['amount']} USDC settled to {payee_id} on {data['target_chain']}")
        return True