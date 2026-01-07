from decimal import Decimal
import uuid

class UAIPEscrow:
    """The Secure Settlement Engine (The Bank of UAIP)."""
    
    def __init__(self):
        self.wallets = {} # {agent_id: balance}
        self.escrow_vault = {} # {contract_id: amount}

    def deposit(self, agent_id, amount):
        self.wallets[agent_id] = self.wallets.get(agent_id, Decimal('0.00')) + Decimal(str(amount))

    def lock_funds(self, payer_id, amount):
        amount = Decimal(str(amount))
        if self.wallets.get(payer_id, 0) < amount:
            raise ValueError("Insufficient Funds")
        
        contract_id = str(uuid.uuid4())
        self.wallets[payer_id] -= amount
        self.escrow_vault[contract_id] = amount
        return contract_id

    def release_to_payee(self, contract_id, payee_id):
        amount = self.escrow_vault.pop(contract_id)
        self.wallets[payee_id] = self.wallets.get(payee_id, Decimal('0.00')) + amount
        return True

    def refund_to_payer(self, contract_id, payer_id):
        amount = self.escrow_vault.pop(contract_id)
        self.wallets[payer_id] += amount
        return True