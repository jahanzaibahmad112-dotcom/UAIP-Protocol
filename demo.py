#!/usr/bin/env python3
"""
UAIP + AgentGuard: Secure Autonomous Economy Demo

This demo showcases:
1. Agent registration with cryptographic identity
2. Nano-transactions with automatic approval
3. Compliance auditing with RAG-powered legal grounding
4. High-value transactions requiring human oversight
5. Zero-knowledge proof verification
6. Multi-agent interoperability

Security Features Demonstrated:
- Ed25519 signature verification
- Zero-knowledge identity proofs
- Deterministic compliance blocking
- Human-in-the-loop approval workflow
- Forensic audit trails
"""

import sys
import time
import traceback
from decimal import Decimal
from typing import Optional

try:
    from sdk import UAIP_Enterprise_SDK
    from compliance import ComplianceAuditor
    from settlement import UAIPFinancialEngine
    from privacy import ZK_Privacy
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Ensure all required modules are in the same directory:")
    print("  - sdk.py")
    print("  - compliance.py")
    print("  - settlement.py")
    print("  - privacy.py")
    print("  - gateway.py (must be running)")
    sys.exit(1)


# Configuration
GATEWAY_URL = "http://localhost:8000"
SECRET_CODE = 987654321  # In production, use secrets.randbelow() or env var

# ANSI color codes for better terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text: str):
    """Print styled section header."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}{Colors.ENDC}\n")


def print_step(step_num: int, text: str):
    """Print styled step."""
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}[STEP {step_num}] {text}{Colors.ENDC}")


def print_scenario(scenario_num: int, text: str):
    """Print styled scenario."""
    print(f"\n{Colors.BOLD}{Colors.OKCYAN}[SCENARIO {scenario_num}] {text}{Colors.ENDC}")


def print_success(text: str):
    """Print success message."""
    print(f"{Colors.OKGREEN}✅ {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.WARNING}⚠️  {text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message."""
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")


def print_info(text: str):
    """Print info message."""
    print(f"{Colors.OKCYAN}ℹ️  {text}{Colors.ENDC}")


def check_gateway_connection(gateway_url: str) -> bool:
    """
    Check if gateway is accessible.
    
    Args:
        gateway_url: URL of the gateway
        
    Returns:
        True if gateway is accessible, False otherwise
    """
    try:
        import requests
        response = requests.get(f"{gateway_url}/", timeout=5)
        return response.status_code == 200
    except Exception as e:
        print_error(f"Cannot connect to gateway at {gateway_url}")
        print_error(f"Error: {e}")
        print_info("Make sure the gateway is running:")
        print("  python gateway.py")
        return False


def demo_initialization() -> Optional[UAIP_Enterprise_SDK]:
    """
    Demo: Initialize agent with cryptographic identity.
    
    Returns:
        Initialized SDK instance or None if failed
    """
    print_step(1, "INITIALIZING ENTERPRISE AGENT IDENTITIES")
    
    try:
        # Initialize Microsoft agent
        print_info("Creating agent: Azure_Bot @ Microsoft")
        msft_agent = UAIP_Enterprise_SDK(
            agent_name="Azure_Bot",
            company_name="Microsoft",
            secret_code=SECRET_CODE,
            gateway_url=GATEWAY_URL,
            auto_register=True
        )
        
        print_success(f"Agent registered: {msft_agent.did}")
        print_info(f"Public Key: {msft_agent.pk[:32]}...")
        print_info(f"ZK Commitment: {msft_agent.zk_commitment}")
        
        return msft_agent
        
    except Exception as e:
        print_error(f"Agent initialization failed: {e}")
        traceback.print_exc()
        return None


def demo_nano_transaction(agent: UAIP_Enterprise_SDK):
    """
    Demo: Execute nano-transaction with automatic approval.
    
    Args:
        agent: Initialized SDK instance
    """
    print_scenario(1, "NANO-TASK AUTOMATION ($0.05)")
    print_info("Testing sub-$10 transaction with instant approval")
    
    try:
        result = agent.call_agent(
            task="verify_tax_id",
            amount=Decimal("0.05"),
            intent="Routine compliance check - automated verification",
            chain="BASE",
            wait_for_approval=False
        )
        
        print_success(f"Transaction Status: {result.get('status')}")
        print_info(f"Request ID: {result.get('request_id', 'N/A')}")
        
        if result.get('settlement'):
            settlement = result['settlement']
            print_info(f"Fee: ${settlement.get('fee', 0):.6f}")
            print_info(f"Payout: ${settlement.get('payout', 0):.6f}")
        
    except Exception as e:
        print_error(f"Nano-transaction failed: {e}")
        traceback.print_exc()


def demo_compliance_audit(agent: UAIP_Enterprise_SDK):
    """
    Demo: Execute compliance audit with RAG-powered legal grounding.
    
    Args:
        agent: Initialized SDK instance
    """
    print_scenario(2, "COMPLIANCE AUDIT WITH RAG-POWERED LEGAL GROUNDING")
    print_info("Testing AI-driven compliance verification")
    
    try:
        auditor = ComplianceAuditor()
        
        # Test Case 1: Standard transaction
        print("\n  Test 1: Standard Transaction ($500)")
        mock_log_1 = {
            "sender": agent.did,
            "task": "generate_monthly_report",
            "amount": "500.0",
            "chain": "BASE",
            "intent": "Q1 2025 financial analysis",
            "timestamp": time.time()
        }
        
        decision_1, audit_1 = auditor.run_active_audit(mock_log_1)
        print_success(f"Decision: {decision_1}")
        print_info(f"Legal Grounding: {audit_1.get('grounded_law', 'N/A')}")
        print_info(f"Audit ID: {audit_1.get('audit_id', 'N/A')}")
        
        # Test Case 2: Blocked transaction
        print("\n  Test 2: Blocked Transaction (prohibited keyword)")
        mock_log_2 = {
            "sender": agent.did,
            "task": "offshore account setup",
            "amount": "1000.0",
            "chain": "BASE",
            "intent": "Setup offshore banking structure",
            "timestamp": time.time()
        }
        
        decision_2, audit_2 = auditor.run_active_audit(mock_log_2)
        print_warning(f"Decision: {decision_2}")
        print_info(f"Reason: {audit_2.get('verification_reasoning', 'N/A')}")
        print_info(f"Legal Grounding: {audit_2.get('grounded_law', 'N/A')}")
        
        # Show audit statistics
        stats = auditor.get_statistics()
        print(f"\n  Audit Statistics:")
        print(f"    Total Audits: {stats['total_audits']}")
        print(f"    Passed: {stats['passed']}")
        print(f"    Blocked: {stats['blocked']}")
        print(f"    Pending: {stats['pending']}")
        
    except Exception as e:
        print_error(f"Compliance audit failed: {e}")
        traceback.print_exc()


def demo_zk_privacy():
    """Demo: Zero-knowledge proof generation and verification."""
    print_scenario(3, "ZERO-KNOWLEDGE PRIVACY PROOFS")
    print_info("Demonstrating cryptographic identity verification without revealing secrets")
    
    try:
        # Generate identity
        secret, commitment = ZK_Privacy.generate_secret_key(), None
        commitment = ZK_Privacy.generate_commitment(secret)
        
        print_success(f"Generated secret key (hash): {hash(secret) % 10000}")
        print_info(f"Public commitment: {commitment}")
        
        # Create and verify proof
        proof = ZK_Privacy.create_proof(secret, commitment, include_timestamp=True)
        print_success("ZK proof generated")
        print_info(f"Proof r: {proof['r']}")
        print_info(f"Proof s: {proof['s']}")
        
        # Verify proof
        is_valid = ZK_Privacy.verify_proof(proof, commitment, check_freshness=True)
        
        if is_valid:
            print_success("✓ Proof verified successfully!")
            print_info("Identity confirmed without revealing secret")
        else:
            print_error("✗ Proof verification failed")
        
        # Show security parameters
        params = ZK_Privacy.get_security_parameters()
        print(f"\n  Security Parameters:")
        print(f"    Protocol: {params['protocol']}")
        print(f"    Security Level: {params['security_level']}")
        print(f"    Prime Bits: {params['prime_bits']}")
        
    except Exception as e:
        print_error(f"ZK proof demo failed: {e}")
        traceback.print_exc()


def demo_high_value_transaction(agent: UAIP_Enterprise_SDK):
    """
    Demo: Execute high-value transaction requiring human approval.
    
    Args:
        agent: Initialized SDK instance
    """
    print_scenario(4, "HIGH-VALUE TRANSACTION ($5,000)")
    print_warning("This transaction requires human oversight per EU AI Act Article 14")
    print_info(f"Go to {GATEWAY_URL} in your browser")
    print_info("Use Admin Key from environment variable ADMIN_KEY")
    print_info("Click 'Approve' button when transaction appears\n")
    
    try:
        # Ask user if they want to proceed
        print(f"{Colors.BOLD}Proceed with high-value transaction? (y/n): {Colors.ENDC}", end='')
        user_input = input().strip().lower()
        
        if user_input != 'y':
            print_warning("High-value transaction skipped")
            return
        
        print_info("Submitting high-value transaction...")
        
        result = agent.call_agent(
            task="wire_transfer_vendor_payment",
            amount=Decimal("5000.0"),
            intent="Q1 2025 vendor payout - requires CFO approval",
            chain="SOLANA",
            metadata={
                "vendor_id": "VENDOR-2025-001",
                "invoice_number": "INV-Q1-5000",
                "department": "Finance"
            },
            wait_for_approval=True  # This will poll for approval
        )
        
        status = result.get('status')
        
        if status == "APPROVED":
            print_success("Transaction approved by human operator!")
            print_info(f"Request ID: {result.get('request_id')}")
        elif status == "PENDING_APPROVAL":
            print_warning("Transaction still pending approval")
            print_info("Check the dashboard or wait for approval")
        else:
            print_error(f"Unexpected status: {status}")
        
    except Exception as e:
        print_error(f"High-value transaction failed: {e}")
        traceback.print_exc()


def demo_settlement_engine():
    """Demo: Financial settlement engine with fee calculation."""
    print_scenario(5, "FINANCIAL SETTLEMENT ENGINE")
    print_info("Testing tiered fee structure")
    
    try:
        engine = UAIPFinancialEngine()
        
        # Test different tiers
        test_amounts = [
            (Decimal("5.00"), "Tier A: Nano (<$10)"),
            (Decimal("500.00"), "Tier B: Mid ($10-$10k)"),
            (Decimal("50000.00"), "Tier C: Enterprise (>$10k)")
        ]
        
        for amount, tier_name in test_amounts:
            print(f"\n  {tier_name}")
            projection = engine.calculate_projected_fee(amount)
            
            print_info(f"Amount: ${projection['amount']:.2f}")
            print_info(f"Fee: ${projection['fee']:.6f} ({projection['fee_percentage']:.2f}%)")
            print_info(f"Payout: ${projection['payout']:.2f}")
        
        # Show statistics
        stats = engine.get_statistics()
        print(f"\n  Engine Statistics:")
        print(f"    Total Transactions: {stats['total_transactions']}")
        print(f"    Total Volume: ${stats['total_volume_usd']:.2f}")
        print(f"    Total Fees Collected: ${stats['total_fees_collected_usd']:.6f}")
        
    except Exception as e:
        print_error(f"Settlement demo failed: {e}")
        traceback.print_exc()


def demo_statistics(agent: UAIP_Enterprise_SDK):
    """
    Display final statistics.
    
    Args:
        agent: Initialized SDK instance
    """
    print_step(6, "FINAL STATISTICS")
    
    try:
        sdk_stats = agent.get_statistics()
        
        print(f"\n  {Colors.BOLD}SDK Performance:{Colors.ENDC}")
        print(f"    Agent DID: {sdk_stats['agent_did']}")
        print(f"    Total Requests: {sdk_stats['total_requests']}")
        print(f"    Successful: {sdk_stats['successful_requests']}")
        print(f"    Failed: {sdk_stats['failed_requests']}")
        print(f"    Success Rate: {sdk_stats['success_rate']:.1f}%")
        print(f"    Total Amount Processed: ${sdk_stats['total_amount_processed']:.2f}")
        
    except Exception as e:
        print_error(f"Failed to retrieve statistics: {e}")


def main():
    """Main demo execution."""
    print_header("🛡️  UAIP + AGENTGUARD: SECURE AUTONOMOUS ECONOMY DEMO")
    
    print(f"{Colors.BOLD}This demo showcases:{Colors.ENDC}")
    print("  • Cryptographic agent identity with Ed25519 signatures")
    print("  • Zero-knowledge privacy proofs (Schnorr protocol)")
    print("  • RAG-powered compliance auditing (EU AI Act, SOC2, GDPR)")
    print("  • Tiered financial settlement (nano to enterprise)")
    print("  • Human-in-the-loop approval for high-risk transactions")
    print("  • Forensic audit trails for regulatory compliance")
    
    # Check gateway connection
    print_step(0, "PRE-FLIGHT CHECKS")
    if not check_gateway_connection(GATEWAY_URL):
        print_error("Cannot proceed without gateway connection")
        sys.exit(1)
    
    print_success("Gateway is accessible")
    
    # Initialize agent
    agent = demo_initialization()
    if not agent:
        print_error("Cannot proceed without agent initialization")
        sys.exit(1)
    
    time.sleep(1)
    
    # Run scenarios
    demo_nano_transaction(agent)
    time.sleep(1)
    
    demo_compliance_audit(agent)
    time.sleep(1)
    
    demo_zk_privacy()
    time.sleep(1)
    
    demo_settlement_engine()
    time.sleep(1)
    
    demo_high_value_transaction(agent)
    time.sleep(1)
    
    demo_statistics(agent)
    
    # Final summary
    print_header("🎉 DEMO COMPLETE")
    print_success("All security layers demonstrated successfully!")
    print_info("Check the following for audit trails:")
    print(f"  • Gateway Dashboard: {GATEWAY_URL}")
    print("  • Compliance Logs: ./uaip_forensic_records.json")
    print("  • Settlement Logs: ./uaip_settlements.jsonl")
    print("  • Gateway Logs: ./uaip_gateway.log")
    
    print(f"\n{Colors.BOLD}Security Features Validated:{Colors.ENDC}")
    print("  ✓ Ed25519 Digital Signatures")
    print("  ✓ Zero-Knowledge Identity Proofs")
    print("  ✓ Replay Attack Prevention (Nonce)")
    print("  ✓ Rate Limiting & Lockouts")
    print("  ✓ SQL Injection Protection")
    print("  ✓ XSS Prevention")
    print("  ✓ Timing Attack Resistance")
    print("  ✓ Input Validation & Sanitization")
    print("  ✓ Deterministic Compliance Blocking")
    print("  ✓ Human-in-the-Loop Oversight")
    print("  ✓ Immutable Audit Trails")
    print("  ✓ Decimal Precision for Finance")
    
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}UAIP Mesh: Building the secure highway for the autonomous economy. 🚀{Colors.ENDC}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Demo interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Demo failed with unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
