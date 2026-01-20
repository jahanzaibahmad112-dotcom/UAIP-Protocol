#!/usr/bin/env python3
"""
AutoGen Multi-Agent Integration with UAIP

This example demonstrates:
1. Multi-agent conversations with UAIP payment capabilities
2. Procurement workflow: Requester → Approver → Payment Executor
3. Function calling for secure payments
4. GroupChat coordination

Prerequisites:
    pip install pyautogen
    export OPENAI_API_KEY="your-key-here"
    python gateway.py  # Must be running
"""

import os
import sys
from decimal import Decimal
from typing import Dict, Any

# Check for required packages
try:
    import autogen
except ImportError:
    print("❌ Missing AutoGen!")
    print("Install with: pip install pyautogen")
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

# AutoGen LLM configuration
config_list = [
    {
        "model": "gpt-4",
        "api_key": OPENAI_API_KEY
    }
]


# ============================================================================
# INITIALIZE UAIP AGENT
# ============================================================================

print("🔧 Initializing UAIP agent...")

uaip_agent = UAIP_Enterprise_SDK(
    agent_name="AutoGenPaymentExecutor",
    company_name="ExampleCorp",
    secret_code=876543210,  # In production: use secrets.randbelow()
    gateway_url=GATEWAY_URL,
    auto_register=True
)

print(f"✅ UAIP agent registered: {uaip_agent.did}\n")


# ============================================================================
# PAYMENT FUNCTION FOR AUTOGEN
# ============================================================================

def make_secure_payment(
    recipient_did: str,
    amount: float,
    purpose: str
) -> Dict[str, Any]:
    """
    Make a secure payment through UAIP gateway.
    
    This function is called by AutoGen agents via function calling.
    
    Args:
        recipient_did: Recipient's DID (e.g., did:uaip:vendor:abc)
        amount: Payment amount in USD
        purpose: Payment purpose/description
        
    Returns:
        Dictionary with payment result
    """
    try:
        print(f"\n💰 Executing payment: ${amount} to {recipient_did[:40]}...")
        
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE",
            wait_for_approval=False
        )
        
        if result['status'] == 'SUCCESS':
            settlement = result['settlement']
            return {
                "success": True,
                "status": "COMPLETED",
                "amount": settlement['amount'],
                "fee": settlement['fee'],
                "payout": settlement['payout'],
                "tx_id": settlement['tx_id'],
                "chain": settlement['chain'],
                "message": f"✅ Payment successful! TX: {settlement['tx_id']}"
            }
        
        elif result['status'] == 'PENDING_APPROVAL':
            return {
                "success": True,
                "status": "PENDING_APPROVAL",
                "request_id": result['request_id'],
                "message": f"⏸️  Payment pending approval. Request ID: {result['request_id']}"
            }
        
        else:
            return {
                "success": False,
                "status": "FAILED",
                "error": str(result),
                "message": f"❌ Payment failed: {result}"
            }
    
    except Exception as e:
        return {
            "success": False,
            "status": "ERROR",
            "error": str(e),
            "message": f"❌ Payment error: {str(e)}"
        }


def check_payment_status(request_id: str) -> Dict[str, Any]:
    """
    Check the status of a pending payment.
    
    Args:
        request_id: UAIP request ID
        
    Returns:
        Status information
    """
    # In production, would call /v1/check/{request_id}
    return {
        "request_id": request_id,
        "status": "PENDING",
        "message": f"Check status at {GATEWAY_URL}"
    }


# ============================================================================
# SCENARIO 1: SIMPLE ASSISTANT WITH PAYMENT
# ============================================================================

def scenario_1_simple_assistant():
    """
    Simple AutoGen assistant with payment capability.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 1: Simple Payment Assistant")
    print("=" * 70)
    print("\nCreating assistant with payment capabilities...\n")
    
    # Define LLM config with function
    llm_config = {
        "config_list": config_list,
        "timeout": 120,
        "functions": [
            {
                "name": "make_secure_payment",
                "description": "Make a secure payment to another agent with automatic compliance checking",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient_did": {
                            "type": "string",
                            "description": "Recipient's DID, must start with 'did:uaip:'"
                        },
                        "amount": {
                            "type": "number",
                            "description": "Payment amount in USD (must be positive)"
                        },
                        "purpose": {
                            "type": "string",
                            "description": "Purpose/description of the payment"
                        }
                    },
                    "required": ["recipient_did", "amount", "purpose"]
                }
            }
        ]
    }
    
    # Create assistant
    assistant = autogen.AssistantAgent(
        name="PaymentAssistant",
        llm_config=llm_config,
        system_message=(
            "You are a payment assistant with access to secure UAIP payment functions. "
            "When asked to make a payment, use the make_secure_payment function. "
            "Always verify the recipient DID starts with 'did:uaip:'. "
            "Payments over $1,000 require human approval. "
            "Be professional and clear about fees and compliance."
        )
    )
    
    # Create user proxy with function mapping
    user_proxy = autogen.UserProxyAgent(
        name="User",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=10,
        code_execution_config=False,
        function_map={
            "make_secure_payment": make_secure_payment
        }
    )
    
    # Initiate conversation
    message = (
        "Please pay did:uaip:vendor:cloud-services $150.00 "
        "for December AWS hosting charges."
    )
    
    print(f"👤 User: {message}\n")
    user_proxy.initiate_chat(assistant, message=message)
    
    print("\n✅ Scenario 1 complete!\n")


# ============================================================================
# SCENARIO 2: MULTI-AGENT APPROVAL WORKFLOW
# ============================================================================

def scenario_2_approval_workflow():
    """
    Multi-agent workflow: Procurement → Finance → Payment.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 2: Multi-Agent Approval Workflow")
    print("=" * 70)
    print("\nCreating procurement workflow with 3 agents...\n")
    
    # LLM config for all agents
    llm_config = {
        "config_list": config_list,
        "timeout": 120
    }
    
    # Agent 1: Procurement (Requester)
    procurement_agent = autogen.AssistantAgent(
        name="ProcurementAgent",
        llm_config=llm_config,
        system_message=(
            "You are a procurement specialist. Your role is to:\n"
            "1. Identify vendor payment needs\n"
            "2. Verify invoice details\n"
            "3. Request approval from FinanceManager\n"
            "4. Provide vendor DID, amount, and purpose clearly\n\n"
            "Always format requests as:\n"
            "Vendor: [DID]\n"
            "Amount: $[amount]\n"
            "Purpose: [description]"
        )
    )
    
    # Agent 2: Finance Manager (Approver)
    finance_agent = autogen.AssistantAgent(
        name="FinanceManager",
        llm_config=llm_config,
        system_message=(
            "You are a finance manager. Your role is to:\n"
            "1. Review payment requests from ProcurementAgent\n"
            "2. Check if amount is reasonable\n"
            "3. Approve payments under $5,000\n"
            "4. Escalate payments over $5,000 to CFO\n"
            "5. Instruct PaymentExecutor to process approved payments\n\n"
            "Be thorough and ask clarifying questions if needed."
        )
    )
    
    # Agent 3: Payment Executor (Action)
    payment_executor = autogen.UserProxyAgent(
        name="PaymentExecutor",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=10,
        code_execution_config=False,
        function_map={
            "make_secure_payment": make_secure_payment
        },
        system_message=(
            "You execute approved payments using the make_secure_payment function. "
            "Only process payments when explicitly approved by FinanceManager. "
            "Report results back to the team."
        )
    )
    
    # Create group chat
    groupchat = autogen.GroupChat(
        agents=[procurement_agent, finance_agent, payment_executor],
        messages=[],
        max_round=15,
        speaker_selection_method="auto"
    )
    
    manager = autogen.GroupChatManager(
        groupchat=groupchat,
        llm_config=llm_config
    )
    
    # Add payment function to manager
    manager.register_function(
        function_map={
            "make_secure_payment": make_secure_payment
        }
    )
    
    # Initiate workflow
    initial_message = (
        "We need to pay our cloud services vendor "
        "did:uaip:vendor:aws-partner $2,500 "
        "for Q1 2024 infrastructure costs. "
        "Please process this payment through the proper approval workflow."
    )
    
    print(f"📋 Initial Request: {initial_message}\n")
    procurement_agent.initiate_chat(manager, message=initial_message)
    
    print("\n✅ Scenario 2 complete!\n")


# ============================================================================
# SCENARIO 3: SEQUENTIAL TASK EXECUTION
# ============================================================================

def scenario_3_sequential_tasks():
    """
    Sequential execution of multiple payments.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 3: Batch Payment Processing")
    print("=" * 70)
    print("\nProcessing multiple vendor payments sequentially...\n")
    
    llm_config = {
        "config_list": config_list,
        "timeout": 120,
        "functions": [
            {
                "name": "make_secure_payment",
                "description": "Make a secure payment",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient_did": {"type": "string"},
                        "amount": {"type": "number"},
                        "purpose": {"type": "string"}
                    },
                    "required": ["recipient_did", "amount", "purpose"]
                }
            }
        ]
    }
    
    assistant = autogen.AssistantAgent(
        name="BatchPaymentProcessor",
        llm_config=llm_config,
        system_message=(
            "You are a batch payment processor. "
            "Process each payment one at a time and report results. "
            "Keep track of successful and failed payments."
        )
    )
    
    user_proxy = autogen.UserProxyAgent(
        name="User",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=20,
        code_execution_config=False,
        function_map={
            "make_secure_payment": make_secure_payment
        }
    )
    
    message = """Process the following vendor payments:

1. did:uaip:vendor:aws-partner - $500 - AWS hosting for December
2. did:uaip:vendor:github-enterprise - $100 - GitHub licenses
3. did:uaip:vendor:slack-workspace - $75 - Slack subscription

Process each payment and provide a summary at the end."""
    
    print(f"👤 User: {message}\n")
    user_proxy.initiate_chat(assistant, message=message)
    
    print("\n✅ Scenario 3 complete!\n")


# ============================================================================
# SCENARIO 4: CONVERSATIONAL FINANCIAL ADVISOR
# ============================================================================

def scenario_4_financial_advisor():
    """
    Interactive financial advisor with payment capabilities.
    """
    print("\n" + "=" * 70)
    print("SCENARIO 4: Interactive Financial Advisor")
    print("=" * 70)
    print("\nCreating conversational financial advisor...\n")
    
    llm_config = {
        "config_list": config_list,
        "timeout": 120,
        "functions": [
            {
                "name": "make_secure_payment",
                "description": "Make a secure payment",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient_did": {"type": "string"},
                        "amount": {"type": "number"},
                        "purpose": {"type": "string"}
                    },
                    "required": ["recipient_did", "amount", "purpose"]
                }
            }
        ]
    }
    
    advisor = autogen.AssistantAgent(
        name="FinancialAdvisor",
        llm_config=llm_config,
        system_message=(
            "You are a helpful financial advisor with payment capabilities. "
            "You can:\n"
            "- Advise on payment strategies\n"
            "- Explain fees (Tier A: <$10 = $0.01, Tier B: $10-$10k = 1%, Tier C: >$10k = $10+0.5%)\n"
            "- Process payments when requested\n"
            "- Warn about compliance requirements\n\n"
            "Be friendly, professional, and security-conscious."
        )
    )
    
    user_proxy = autogen.UserProxyAgent(
        name="User",
        human_input_mode="TERMINATE",  # Allow human input
        max_consecutive_auto_reply=10,
        code_execution_config=False,
        function_map={
            "make_secure_payment": make_secure_payment
        }
    )
    
    # Start interactive session
    print("💬 You can now chat with the Financial Advisor")
    print("   Try asking about payments, fees, or request a payment")
    print("   Type 'exit' to end the conversation\n")
    
    user_proxy.initiate_chat(
        advisor,
        message="Hello! I need help making a payment to a vendor."
    )


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run all scenarios."""
    
    print("=" * 70)
    print("🤖 AUTOGEN + UAIP MULTI-AGENT DEMO")
    print("=" * 70)
    print()
    print("This demo shows AutoGen agents with UAIP payment capabilities:")
    print("  1. Simple payment assistant")
    print("  2. Multi-agent approval workflow")
    print("  3. Batch payment processing")
    print("  4. Interactive financial advisor")
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
        scenario_1_simple_assistant()
        
        input("\nPress Enter to continue to Scenario 2...")
        scenario_2_approval_workflow()
        
        input("\nPress Enter to continue to Scenario 3...")
        scenario_3_sequential_tasks()
        
        # Optional: Interactive mode
        print("\n" + "=" * 70)
        choice = input("\nRun interactive financial advisor? (y/n): ").strip().lower()
        if choice == 'y':
            scenario_4_financial_advisor()
        
        print("\n" + "=" * 70)
        print("🎉 All scenarios complete!")
        print("=" * 70)
        print("\nKey takeaways:")
        print("  ✅ AutoGen agents can make secure UAIP payments")
        print("  ✅ Multi-agent workflows enable approval processes")
        print("  ✅ Function calling integrates seamlessly")
        print("  ✅ Compliance is automatic and transparent")
        print()
        
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
