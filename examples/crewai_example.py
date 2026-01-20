#!/usr/bin/env python3
"""
CrewAI Integration with UAIP

This example demonstrates:
1. Creating a Crew of specialized agents with UAIP payment capabilities
2. Sequential task execution with financial workflows
3. Custom tools for secure payments
4. Multi-step procurement automation

Prerequisites:
    pip install crewai crewai-tools
    export OPENAI_API_KEY="your-key-here"
    python gateway.py  # Must be running
"""

import os
import sys
from decimal import Decimal
from typing import Dict, Any

# Check for required packages
try:
    from crewai import Agent, Task, Crew, Process
    from crewai_tools import tool
except ImportError:
    print("❌ Missing CrewAI!")
    print("Install with: pip install crewai crewai-tools")
    sys.exit(1)

try:
    from uaip.sdk import UAIP_Enterprise_SDK
except ImportError:
    print("❌ Cannot import UAIP SDK!")
    print("Make sure you're running from the repository root directory")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    print("❌ OPENAI_API_KEY environment variable not set!")
    print("Set it with: export OPENAI_API_KEY='your-key-here'")
    sys.exit(1)


# ============================================================================
# INITIALIZE UAIP AGENT
# ============================================================================

print("🔧 Initializing UAIP agent...")

uaip_agent = UAIP_Enterprise_SDK(
    agent_name="CrewAIPaymentExecutor",
    company_name="ExampleCorp",
    secret_code=765432109,  # In production: use secrets.randbelow()
    gateway_url=GATEWAY_URL,
    auto_register=True
)

print(f"✅ UAIP agent registered: {uaip_agent.did}\n")


# ============================================================================
# CREWAI TOOLS FOR UAIP
# ============================================================================

@tool("Secure Payment Tool")
def make_payment(recipient_did: str, amount: float, purpose: str) -> str:
    """
    Make a secure payment through UAIP gateway.
    
    This tool processes payments with automatic compliance checking.
    Payments over $1,000 require human approval.
    
    Args:
        recipient_did: Recipient's DID (must start with 'did:uaip:')
        amount: Payment amount in USD (must be positive)
        purpose: Payment purpose/description
        
    Returns:
        Payment result as formatted string
    """
    try:
        # Validate inputs
        if not recipient_did.startswith("did:uaip:"):
            return f"❌ Invalid recipient DID: {recipient_did}. Must start with 'did:uaip:'"
        
        if amount <= 0:
            return f"❌ Amount must be positive, got: ${amount}"
        
        # Execute payment
        print(f"\n💰 Processing payment: ${amount} to {recipient_did[:40]}...")
        
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE",
            wait_for_approval=False
        )
        
        # Format response
        if result['status'] == 'SUCCESS':
            s = result['settlement']
            return (
                f"✅ PAYMENT SUCCESSFUL\n"
                f"Amount: ${s['amount']}\n"
                f"Fee: ${s['fee']} ({s['fee_percentage']:.2f}%) - Tier {s['tier']}\n"
                f"Payout: ${s['payout']}\n"
                f"Chain: {s['chain']}\n"
                f"TX ID: {s['tx_id']}\n"
                f"Processing Time: {s['processing_time_ms']:.2f}ms"
            )
        
        elif result['status'] == 'PENDING_APPROVAL':
            return (
                f"⏸️  PAYMENT PENDING APPROVAL\n"
                f"Amount: ${amount} requires human approval (≥$1,000)\n"
                f"Request ID: {result['request_id']}\n"
                f"Dashboard: {GATEWAY_URL}\n"
                f"Please approve in the UAIP dashboard to complete payment."
            )
        
        else:
            return f"❌ Payment failed: {result}"
    
    except Exception as e:
        return f"❌ Payment error: {str(e)}"


@tool("Payment Status Checker")
def check_payment_status(request_id: str) -> str:
    """
    Check the status of a pending payment.
    
    Args:
        request_id: UAIP request ID from a pending payment
        
    Returns:
        Status information
    """
    try:
        import requests
        response = requests.get(
            f"{GATEWAY_URL}/v1/check/{request_id}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            status = data.get('status', 'UNKNOWN')
            return (
                f"📊 Payment Status\n"
                f"Request ID: {request_id}\n"
                f"Status: {status}\n"
                f"Check dashboard at: {GATEWAY_URL}"
            )
        else:
            return f"❌ Failed to check status: HTTP {response.status_code}"
    
    except Exception as e:
        return f"❌ Error checking status: {str(e)}"


@tool("Transaction Statistics")
def get_transaction_stats() -> str:
    """
    Get UAIP agent transaction statistics.
    
    Returns:
        Formatted statistics report
    """
    try:
        stats = uaip_agent.get_statistics()
        
        return (
            f"📊 TRANSACTION STATISTICS\n"
            f"Agent: {stats['agent_name']}\n"
            f"DID: {stats['agent_did']}\n"
            f"Company: {stats['company_name']}\n\n"
            f"Performance:\n"
            f"  Total Requests: {stats['total_requests']}\n"
            f"  Successful: {stats['successful_requests']}\n"
            f"  Failed: {stats['failed_requests']}\n"
            f"  Success Rate: {stats['success_rate']:.1f}%\n\n"
            f"Financial:\n"
            f"  Total Processed: ${stats['total_amount_processed']:.2f}"
        )
    
    except Exception as e:
        return f"❌ Error getting statistics: {str(e)}"


@tool("Fee Calculator")
def calculate_payment_fee(amount: float) -> str:
    """
    Calculate the fee for a given payment amount.
    
    UAIP uses tiered fees:
    - Tier A (≤$10): $0.01 flat fee
    - Tier B ($10-$10k): 1.0% of amount
    - Tier C (>$10k): $10 + 0.5% of amount
    
    Args:
        amount: Payment amount in USD
        
    Returns:
        Fee breakdown
    """
    try:
        amount_dec = Decimal(str(amount))
        
        # Calculate fee based on tier
        if amount_dec <= Decimal("10"):
            fee = Decimal("0.01")
            tier = "A"
            description = "Flat fee for nano-transactions"
        elif amount_dec <= Decimal("10000"):
            fee = amount_dec * Decimal("0.01")  # 1.0%
            tier = "B"
            description = "1.0% fee for mid-range transactions"
        else:
            fee = Decimal("10") + (amount_dec * Decimal("0.005"))  # $10 + 0.5%
            tier = "C"
            description = "$10 base + 0.5% fee for enterprise transactions"
        
        payout = amount_dec - fee
        fee_percentage = (fee / amount_dec * 100) if amount_dec > 0 else 0
        
        return (
            f"💰 FEE CALCULATION\n"
            f"Amount: ${amount_dec}\n"
            f"Tier: {tier} - {description}\n"
            f"Fee: ${fee} ({fee_percentage:.2f}%)\n"
            f"Net Payout: ${payout}"
        )
    
    except Exception as e:
        return f"❌ Error calculating fee: {str(e)}"


# ============================================================================
# SCENARIO 1: SIMPLE PROCUREMENT WORKFLOW
# ============================================================================

def scenario_1_simple_procurement():
    """
    Simple procurement: Verify invoice → Make payment.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 1: Simple Procurement Workflow")
    print("=" * 70)
    print("\nCreating procurement crew...\n")
    
    # Agent 1: Invoice Validator
    invoice_validator = Agent(
        role='Invoice Validator',
        goal='Verify invoice details and ensure accuracy',
        backstory=(
            "You are an expert in accounts payable with 10 years of experience. "
            "Your role is to carefully review invoices for accuracy, completeness, "
            "and legitimacy before payment processing."
        ),
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 2: Payment Processor
    payment_processor = Agent(
        role='Payment Processor',
        goal='Execute approved payments securely through UAIP',
        backstory=(
            "You are responsible for executing financial transactions securely. "
            "You use the Secure Payment Tool to process payments with automatic "
            "compliance checking and audit trails."
        ),
        tools=[make_payment, calculate_payment_fee],
        verbose=True,
        allow_delegation=False
    )
    
    # Task 1: Validate invoice
    validate_task = Task(
        description=(
            "Review this invoice:\n"
            "Vendor: did:uaip:vendor:aws-partner\n"
            "Amount: $450.00\n"
            "Purpose: AWS hosting for December 2024\n"
            "Invoice #: INV-2024-12-001\n\n"
            "Verify the invoice details and provide a recommendation."
        ),
        agent=invoice_validator,
        expected_output=(
            "Invoice validation report with recommendation "
            "(APPROVE or REJECT with reasoning)"
        )
    )
    
    # Task 2: Process payment
    payment_task = Task(
        description=(
            "If the invoice is approved, use the Secure Payment Tool to process the payment. "
            "First calculate the expected fee, then execute the payment."
        ),
        agent=payment_processor,
        expected_output="Payment confirmation with transaction details"
    )
    
    # Create crew
    crew = Crew(
        agents=[invoice_validator, payment_processor],
        tasks=[validate_task, payment_task],
        process=Process.sequential,
        verbose=2
    )
    
    # Execute
    print("\n🚀 Starting procurement workflow...\n")
    result = crew.kickoff()
    
    print("\n" + "=" * 70)
    print("RESULT:")
    print("=" * 70)
    print(result)
    print("\n✅ Scenario 1 complete!\n")


# ============================================================================
# SCENARIO 2: MULTI-VENDOR PAYMENT PROCESSING
# ============================================================================

def scenario_2_batch_payments():
    """
    Process multiple vendor payments with validation and compliance.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 2: Batch Vendor Payment Processing")
    print("=" * 70)
    print("\nCreating batch processing crew...\n")
    
    # Agent 1: Vendor Manager
    vendor_manager = Agent(
        role='Vendor Manager',
        goal='Manage vendor relationships and validate vendor information',
        backstory=(
            "You maintain vendor records and ensure all vendor information "
            "is accurate and up-to-date. You verify DIDs and payment details."
        ),
        verbose=True,
        allow_delegation=True
    )
    
    # Agent 2: Finance Controller
    finance_controller = Agent(
        role='Finance Controller',
        goal='Ensure payments are within budget and properly categorized',
        backstory=(
            "You oversee the company's financial operations. You review all "
            "payments for budget compliance and proper expense categorization."
        ),
        verbose=True,
        allow_delegation=True
    )
    
    # Agent 3: Payment Executor
    payment_executor = Agent(
        role='Payment Executor',
        goal='Execute approved payments efficiently',
        backstory=(
            "You process approved payments through UAIP with attention to "
            "security, compliance, and timely execution."
        ),
        tools=[make_payment, calculate_payment_fee, get_transaction_stats],
        verbose=True,
        allow_delegation=False
    )
    
    # Task 1: Vendor validation
    vendor_task = Task(
        description=(
            "Validate these vendor payment requests:\n\n"
            "1. AWS Partner (did:uaip:vendor:aws-partner) - $850\n"
            "   Purpose: Cloud hosting services\n\n"
            "2. GitHub Enterprise (did:uaip:vendor:github-ent) - $300\n"
            "   Purpose: Developer tool licenses\n\n"
            "3. Slack Workspace (did:uaip:vendor:slack-pro) - $120\n"
            "   Purpose: Team communication platform\n\n"
            "Verify all vendor DIDs are properly formatted."
        ),
        agent=vendor_manager,
        expected_output="Vendor validation report for all 3 vendors"
    )
    
    # Task 2: Budget approval
    budget_task = Task(
        description=(
            "Review the validated vendor payments for budget compliance. "
            "Total budget for software/infrastructure: $2,000/month. "
            "Approve or flag any concerns."
        ),
        agent=finance_controller,
        expected_output="Budget approval decision with reasoning"
    )
    
    # Task 3: Execute payments
    execution_task = Task(
        description=(
            "Execute all approved payments using the Secure Payment Tool. "
            "Process each payment sequentially and provide a summary. "
            "After all payments, show transaction statistics."
        ),
        agent=payment_executor,
        expected_output=(
            "Payment execution summary with transaction IDs and statistics"
        )
    )
    
    # Create crew
    crew = Crew(
        agents=[vendor_manager, finance_controller, payment_executor],
        tasks=[vendor_task, budget_task, execution_task],
        process=Process.sequential,
        verbose=2
    )
    
    # Execute
    print("\n🚀 Starting batch payment processing...\n")
    result = crew.kickoff()
    
    print("\n" + "=" * 70)
    print("RESULT:")
    print("=" * 70)
    print(result)
    print("\n✅ Scenario 2 complete!\n")


# ============================================================================
# SCENARIO 3: HIGH-VALUE TRANSACTION WORKFLOW
# ============================================================================

def scenario_3_high_value_transaction():
    """
    Handle high-value transaction requiring CFO approval.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 3: High-Value Transaction ($5,000)")
    print("=" * 70)
    print("\nCreating approval workflow crew...\n")
    
    # Agent 1: Procurement Manager
    procurement_manager = Agent(
        role='Procurement Manager',
        goal='Request and justify high-value purchases',
        backstory=(
            "You identify business needs and request necessary purchases. "
            "You provide detailed justification for high-value transactions."
        ),
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 2: CFO Advisor
    cfo_advisor = Agent(
        role='CFO Advisor',
        goal='Analyze financial impact and provide recommendations',
        backstory=(
            "You advise on high-value financial decisions. You analyze ROI, "
            "budget impact, and provide recommendations to the CFO."
        ),
        tools=[calculate_payment_fee],
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 3: Payment Coordinator
    payment_coordinator = Agent(
        role='Payment Coordinator',
        goal='Coordinate payment execution and approvals',
        backstory=(
            "You manage the payment approval process. For high-value transactions, "
            "you initiate the payment and monitor approval status."
        ),
        tools=[make_payment, check_payment_status],
        verbose=True,
        allow_delegation=False
    )
    
    # Task 1: Procurement request
    request_task = Task(
        description=(
            "Prepare a procurement request for:\n"
            "Vendor: did:uaip:vendor:consulting-firm\n"
            "Amount: $5,000\n"
            "Purpose: Q1 2025 strategic consulting engagement\n\n"
            "Provide detailed business justification."
        ),
        agent=procurement_manager,
        expected_output="Detailed procurement request with business justification"
    )
    
    # Task 2: Financial analysis
    analysis_task = Task(
        description=(
            "Analyze the $5,000 consulting engagement request. "
            "Calculate the UAIP fee, total cost, and provide ROI analysis. "
            "Make a recommendation."
        ),
        agent=cfo_advisor,
        expected_output="Financial analysis with recommendation"
    )
    
    # Task 3: Payment initiation
    payment_task = Task(
        description=(
            "If approved by analysis, initiate the payment using Secure Payment Tool. "
            "This payment will require human approval in the UAIP dashboard. "
            "Provide the request ID and instructions for approval."
        ),
        agent=payment_coordinator,
        expected_output=(
            "Payment initiation confirmation with request ID and approval instructions"
        )
    )
    
    # Create crew
    crew = Crew(
        agents=[procurement_manager, cfo_advisor, payment_coordinator],
        tasks=[request_task, analysis_task, payment_task],
        process=Process.sequential,
        verbose=2
    )
    
    # Execute
    print("\n🚀 Starting high-value transaction workflow...\n")
    result = crew.kickoff()
    
    print("\n" + "=" * 70)
    print("RESULT:")
    print("=" * 70)
    print(result)
    print("\n" + "=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print(f"1. Open dashboard: {GATEWAY_URL}")
    print("2. Find the pending transaction")
    print("3. Click 'Approve' and enter admin key")
    print("4. Payment will be executed automatically")
    print("\n✅ Scenario 3 complete!\n")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run all scenarios."""
    
    print("=" * 70)
    print("👥 CREWAI + UAIP INTEGRATION DEMO")
    print("=" * 70)
    print()
    print("This demo shows CrewAI agents with UAIP payment capabilities:")
    print("  1. Simple procurement workflow")
    print("  2. Batch vendor payment processing")
    print("  3. High-value transaction approval")
    print()
    print("=" * 70)
    
    # Check gateway
    import requests
    try:
        response = requests.get(f"{GATEWAY_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"\n❌ Gateway unhealthy at {GATEWAY_URL}")
            print("Start it with: python gateway.py\n")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print(f"\n❌ Cannot connect to gateway at {GATEWAY_URL}")
        print("Start it with: python gateway.py\n")
        sys.exit(1)
    
    print("\n✅ Gateway is accessible\n")
    
    # Run scenarios
    try:
        scenario_1_simple_procurement()
        
        input("\nPress Enter to continue to Scenario 2...")
        scenario_2_batch_payments()
        
        input("\nPress Enter to continue to Scenario 3...")
        scenario_3_high_value_transaction()
        
        print("\n" + "=" * 70)
        print("🎉 All scenarios complete!")
        print("=" * 70)
        print("\nKey takeaways:")
        print("  ✅ CrewAI agents can make secure UAIP payments")
        print("  ✅ Sequential task execution enables complex workflows")
        print("  ✅ Custom tools integrate seamlessly")
        print("  ✅ Compliance and approvals are automatic")
        print("  ✅ Specialized agents handle different roles")
        print()
        
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
