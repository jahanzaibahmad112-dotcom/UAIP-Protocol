#!/usr/bin/env python3
"""
LangChain Integration Example with UAIP

This example demonstrates:
1. Creating a LangChain agent with UAIP payment capabilities
2. Using the agent to process financial tasks
3. Automatic compliance checking and settlement
4. Conversational interface with payment tools

Prerequisites:
    pip install langchain langchain-openai
    export OPENAI_API_KEY="your-key-here"
    python gateway.py  # Must be running
"""

import os
import sys
from decimal import Decimal
from typing import Optional

# Check for required packages
try:
    from langchain.agents import Tool, initialize_agent, AgentType
    from langchain.memory import ConversationBufferMemory
    from langchain_openai import ChatOpenAI
except ImportError:
    print("❌ Missing dependencies!")
    print("Install with: pip install langchain langchain-openai")
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
    agent_name="LangChainFinancialAssistant",
    company_name="ExampleCorp",
    secret_code=987654321,  # In production: use secrets.randbelow()
    gateway_url=GATEWAY_URL,
    auto_register=True
)

print(f"✅ UAIP agent registered: {uaip_agent.did}\n")


# ============================================================================
# CREATE PAYMENT TOOL
# ============================================================================

def make_secure_payment(input_string: str) -> str:
    """
    Make a secure payment through UAIP gateway.
    
    Input format: "recipient_did|amount|purpose"
    Example: "did:uaip:vendor:abc123|150.00|Invoice payment"
    
    Args:
        input_string: Pipe-separated payment details
        
    Returns:
        Human-readable payment result
    """
    try:
        # Parse input
        parts = input_string.split("|")
        if len(parts) != 3:
            return "❌ Invalid input format. Use: recipient_did|amount|purpose"
        
        recipient, amount_str, purpose = parts
        
        # Validate inputs
        if not recipient.startswith("did:uaip:"):
            return f"❌ Invalid recipient DID: {recipient}. Must start with 'did:uaip:'"
        
        try:
            amount = Decimal(amount_str)
        except Exception:
            return f"❌ Invalid amount: {amount_str}. Must be a number."
        
        if amount <= 0:
            return "❌ Amount must be greater than zero"
        
        # Execute payment
        print(f"\n💰 Processing payment: ${amount} to {recipient[:30]}...")
        
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=amount,
            intent=purpose,
            chain="BASE",
            wait_for_approval=False  # Don't block LangChain workflow
        )
        
        # Format response based on status
        if result['status'] == 'SUCCESS':
            settlement = result['settlement']
            return (
                f"✅ Payment successful!\n"
                f"   Amount: ${settlement['amount']}\n"
                f"   Fee: ${settlement['fee']} ({settlement['fee_percentage']:.2f}%)\n"
                f"   Net payout: ${settlement['payout']}\n"
                f"   Chain: {settlement['chain']}\n"
                f"   TX ID: {settlement['tx_id']}\n"
                f"   Tier: {settlement['tier']}"
            )
        
        elif result['status'] == 'PENDING_APPROVAL':
            return (
                f"⏸️  Payment requires human approval (amount ≥ $1,000)\n"
                f"   Request ID: {result['request_id']}\n"
                f"   Dashboard: {GATEWAY_URL}\n"
                f"   Please approve in the UAIP dashboard to complete payment."
            )
        
        else:
            return f"❌ Payment failed: {result}"
    
    except Exception as e:
        return f"❌ Payment error: {str(e)}"


def check_agent_balance(input_string: str) -> str:
    """
    Check UAIP agent statistics (demo function).
    
    Args:
        input_string: Ignored (for compatibility)
        
    Returns:
        Agent statistics
    """
    try:
        stats = uaip_agent.get_statistics()
        
        return (
            f"📊 Agent Statistics:\n"
            f"   Agent: {stats['agent_name']}\n"
            f"   DID: {stats['agent_did']}\n"
            f"   Total Requests: {stats['total_requests']}\n"
            f"   Successful: {stats['successful_requests']}\n"
            f"   Failed: {stats['failed_requests']}\n"
            f"   Success Rate: {stats['success_rate']:.1f}%\n"
            f"   Total Processed: ${stats['total_amount_processed']:.2f}"
        )
    
    except Exception as e:
        return f"❌ Error checking balance: {str(e)}"


# Create LangChain tools
payment_tool = Tool(
    name="SecurePayment",
    func=make_secure_payment,
    description=(
        "Make a secure payment to another agent with automatic compliance checking. "
        "Input format: 'recipient_did|amount|purpose'. "
        "Example: 'did:uaip:vendor:abc|150.00|Invoice payment for Q4 services'. "
        "Payments over $1,000 require human approval and will return PENDING status."
    )
)

balance_tool = Tool(
    name="CheckAgentStats",
    func=check_agent_balance,
    description=(
        "Check the UAIP agent's transaction statistics including total processed amount, "
        "success rate, and request count. Input can be anything (ignored)."
    )
)


# ============================================================================
# INITIALIZE LANGCHAIN AGENT
# ============================================================================

print("🦜 Initializing LangChain agent with UAIP tools...")

# Create LLM
llm = ChatOpenAI(
    temperature=0,
    model="gpt-4",  # Use gpt-3.5-turbo for faster/cheaper
    openai_api_key=OPENAI_API_KEY
)

# Create memory for conversational context
memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True
)

# Initialize agent with tools
agent = initialize_agent(
    tools=[payment_tool, balance_tool],
    llm=llm,
    agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    memory=memory,
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=5
)

print("✅ LangChain agent initialized with UAIP payment capabilities\n")


# ============================================================================
# DEMO SCENARIOS
# ============================================================================

def run_demo():
    """Run interactive demo scenarios."""
    
    print("=" * 70)
    print("🎯 LANGCHAIN + UAIP DEMO")
    print("=" * 70)
    print()
    print("This demo shows a LangChain agent with secure payment capabilities.")
    print("The agent can:")
    print("  • Make payments to other agents")
    print("  • Check transaction statistics")
    print("  • Handle compliance automatically")
    print("  • Require human approval for high-value transactions")
    print()
    print("=" * 70)
    print()
    
    # Scenario 1: Simple payment
    print("\n" + "=" * 70)
    print("SCENARIO 1: Small Payment ($50)")
    print("=" * 70)
    
    query1 = (
        "Pay did:uaip:vendor:cloud-services $50.00 for December AWS credits. "
        "Use the SecurePayment tool."
    )
    
    print(f"\n👤 User: {query1}\n")
    response1 = agent.run(query1)
    print(f"\n🤖 Agent: {response1}\n")
    
    # Scenario 2: Check statistics
    print("\n" + "=" * 70)
    print("SCENARIO 2: Check Agent Statistics")
    print("=" * 70)
    
    query2 = "Show me my transaction statistics using CheckAgentStats"
    
    print(f"\n👤 User: {query2}\n")
    response2 = agent.run(query2)
    print(f"\n🤖 Agent: {response2}\n")
    
    # Scenario 3: High-value payment (requires approval)
    print("\n" + "=" * 70)
    print("SCENARIO 3: High-Value Payment ($5,000)")
    print("=" * 70)
    
    query3 = (
        "Pay did:uaip:vendor:consulting-firm $5000.00 for Q1 strategic consulting. "
        "This is a high-value payment that will require CFO approval."
    )
    
    print(f"\n👤 User: {query3}\n")
    response3 = agent.run(query3)
    print(f"\n🤖 Agent: {response3}\n")
    
    # Scenario 4: Conversational follow-up
    print("\n" + "=" * 70)
    print("SCENARIO 4: Conversational Context")
    print("=" * 70)
    
    query4 = "What was the total amount I've processed so far?"
    
    print(f"\n👤 User: {query4}\n")
    response4 = agent.run(query4)
    print(f"\n🤖 Agent: {response4}\n")
    
    # Interactive mode
    print("\n" + "=" * 70)
    print("INTERACTIVE MODE")
    print("=" * 70)
    print("\nYou can now chat with the agent directly.")
    print("Try asking things like:")
    print("  • 'Pay did:uaip:vendor:abc $200 for services'")
    print("  • 'Show my statistics'")
    print("  • 'What payments have I made?'")
    print("\nType 'exit' to quit.\n")
    
    while True:
        try:
            user_input = input("👤 You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['exit', 'quit', 'bye']:
                print("\n👋 Goodbye!\n")
                break
            
            response = agent.run(user_input)
            print(f"\n🤖 Agent: {response}\n")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!\n")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


# ============================================================================
# ADVANCED EXAMPLE: CUSTOM AGENT WITH SYSTEM PROMPT
# ============================================================================

def create_financial_assistant():
    """
    Create a specialized financial assistant agent with custom system prompt.
    """
    from langchain.prompts import MessagesPlaceholder, ChatPromptTemplate
    from langchain.agents import AgentExecutor
    from langchain.agents.format_scratchpad import format_to_openai_function_messages
    from langchain.agents.output_parsers import OpenAIFunctionsAgentOutputParser
    
    # Custom system message
    system_message = """You are a professional financial assistant with secure payment capabilities through UAIP.

Your responsibilities:
1. Help users make secure payments to vendors and service providers
2. Verify payment details before processing
3. Explain compliance requirements (EU AI Act, SOC2, GDPR)
4. Warn users about high-value transactions that need approval
5. Track transaction statistics

Important rules:
- Always verify the recipient DID starts with "did:uaip:"
- For payments over $1,000, warn that human approval is required
- Be clear about fees: <$10 = $0.01, $10-$10k = 1%, >$10k = $10 + 0.5%
- Suggest appropriate blockchain (BASE for general, SOLANA for speed)

You have access to:
- SecurePayment: Make payments with compliance checking
- CheckAgentStats: View transaction history and statistics

Always be professional, accurate, and security-conscious."""
    
    print("\n🏦 Creating specialized Financial Assistant...\n")
    
    # This is a more advanced pattern - showing what's possible
    # For beginners, the simple initialize_agent approach above is recommended
    
    return agent  # Return the simpler agent for this demo


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    try:
        # Check if gateway is running
        import requests
        try:
            response = requests.get(f"{GATEWAY_URL}/health", timeout=5)
            if response.status_code != 200:
                print(f"❌ Gateway unhealthy at {GATEWAY_URL}")
                print("Start it with: python gateway.py")
                sys.exit(1)
        except requests.exceptions.RequestException:
            print(f"❌ Cannot connect to gateway at {GATEWAY_URL}")
            print("Start it with: python gateway.py")
            sys.exit(1)
        
        # Run demo
        run_demo()
    
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
