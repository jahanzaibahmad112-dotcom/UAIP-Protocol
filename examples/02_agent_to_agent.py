"""
Agent-to-Agent Transaction
Demonstrates secure payment between two agents from different companies.
"""

from uaip.sdk import UAIP_Enterprise_SDK


def main():
    print("🤝 Agent-to-Agent Transaction Example\n")
    
    # Create agents from two different companies
    print("1️⃣ Creating agents...")
    alice = UAIPAgent(name="ProcurementAgent", company="CompanyA")
    bob = UAIPAgent(name="FinanceAgent", company="CompanyB")
    
    print(f"\n✅ Alice (CompanyA): {alice.did[:20]}...")
    print(f"✅ Bob (CompanyB): {bob.did[:20]}...")
    
    # Verify both agents' identities
    print("\n2️⃣ Verifying identities...")
    alice_verified = alice.verify_identity()
    bob_verified = bob.verify_identity()
    print(f"✅ Alice verified: {alice_verified}")
    print(f"✅ Bob verified: {bob_verified}")
    
    # Alice requests authorization to pay Bob
    print("\n3️⃣ Requesting JIT authorization...")
    auth_token = alice.request_authorization(
        action="payment",
        target=bob.did,
        amount=150.00
    )
    print(f"✅ Authorization granted (expires in 60 seconds)")
    print(f"Token: {auth_token[:20]}...")
    
    # Check compliance before payment
    print("\n4️⃣ Running compliance check...")
    compliance = alice.check_compliance(
        action="payment",
        amount=150.00,
        recipient=bob.did
    )
    print(f"✅ Compliance check passed")
    print(f"   - EU AI Act: {compliance['eu_ai_act']}")
    print(f"   - SOC2: {compliance['soc2']}")
    print(f"   - GDPR: {compliance['gdpr']}")
    
    # Execute the payment
    print("\n5️⃣ Executing payment...")
    
    receipt = alice.pay(
        to_agent=bob.did,
        amount=150.00,
        purpose="Q4 Invoice Processing Service",
        chain="BASE"
    )
    
    print(f"\n📧 Receipt:")
    print(f"   From: {receipt.from_agent[:30]}...")
    print(f"   To: {receipt.to_agent[:30]}...")
    print(f"   Amount: ${receipt.amount_usd}")
    print(f"   USDC: {receipt.amount_usdc}")
    print(f"   Protocol Tax: ${receipt.protocol_tax}")
    print(f"   Chain: {receipt.chain}")
    print(f"   TX Hash: {receipt.tx_hash}")
    print(f"   Status: {receipt.status}")
    
    print("\n✅ Transaction complete! Audit log created.")


if __name__ == "__main__":
    main()
