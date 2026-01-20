# 🔌 UAIP Framework Integrations

How to integrate UAIP secure settlement into popular AI agent frameworks.

---

## 🦜 LangChain Integration

Add secure payments and compliance to your LangChain agents.

### Installation

```bash
pip install uaip langchain langchain-openai
```

### Basic Integration

```python
from langchain.agents import Tool, initialize_agent, AgentType
from langchain_openai import ChatOpenAI
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

# Initialize UAIP agent
uaip_agent = UAIP_Enterprise_SDK(
    agent_name="LangChainBot",
    company_name="MyCompany",
    secret_code=123456789,
    gateway_url="http://localhost:8000",
    auto_register=True
)

# Create payment tool
def make_payment(input_str: str) -> str:
    """
    Make a secure payment to another agent.
    
    Args:
        input_str: Format "recipient_did|amount|purpose"
    
    Returns:
        Payment result description
    """
    try:
        recipient, amount, purpose = input_str.split("|")
        
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(amount),
            intent=purpose,
            chain="BASE"
        )
        
        if result['status'] == 'SUCCESS':
            settlement = result['settlement']
            return f"✅ Payment successful! Paid ${settlement['amount']}, Fee: ${settlement['fee']}, TX: {settlement['tx_id']}"
        elif result['status'] == 'PENDING_APPROVAL':
            return f"⏸️ Payment pending approval. Request ID: {result['request_id']}"
        else:
            return f"❌ Payment failed: {result}"
            
    except Exception as e:
        return f"❌ Payment error: {str(e)}"

# Create LangChain tool
payment_tool = Tool(
    name="SecurePayment",
    func=make_payment,
    description="Make a secure payment to another agent. Input format: 'recipient_did|amount|purpose'. Example: 'did:uaip:vendor:abc|150.00|Invoice payment'"
)

# Initialize agent with payment capability
llm = ChatOpenAI(temperature=0, model="gpt-4")

agent = initialize_agent(
    tools=[payment_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# Use the agent
result = agent.run(
    "Pay the vendor with DID did:uaip:vendor:xyz123 $250 for the Q4 consulting services"
)

print(result)
```

### Advanced: UAIP as Memory Backend

```python
from langchain.memory import ConversationBufferMemory
from typing import Dict, List, Any

class UAIPMemory(ConversationBufferMemory):
    """Store conversation history with UAIP audit trail."""
    
    def __init__(self, uaip_agent: UAIP_Enterprise_SDK, **kwargs):
        super().__init__(**kwargs)
        self.uaip = uaip_agent
    
    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, str]) -> None:
        """Save conversation with UAIP logging."""
        super().save_context(inputs, outputs)
        
        # Log to UAIP audit trail
        # (In production, store in separate audit system)
        print(f"📝 Logged to UAIP: {inputs} -> {outputs}")

# Usage
memory = UAIPMemory(uaip_agent=uaip_agent)

agent = initialize_agent(
    tools=[payment_tool],
    llm=llm,
    agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
    memory=memory,
    verbose=True
)
```

### LangChain Example: Financial Assistant

```python
from langchain.prompts import PromptTemplate

template = """You are a financial assistant with secure payment capabilities.

You have access to:
- SecurePayment: Make payments with automatic compliance checking

When making payments:
1. Always verify the amount is correct
2. Check if the recipient DID is valid (starts with "did:uaip:")
3. Provide a clear purpose/reason
4. Payments over $1,000 require human approval

Available tools: {tools}
Tool names: {tool_names}

Question: {input}
{agent_scratchpad}
"""

prompt = PromptTemplate(
    template=template,
    input_variables=["input", "tools", "tool_names", "agent_scratchpad"]
)

agent = initialize_agent(
    tools=[payment_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    agent_kwargs={"prefix": template},
    verbose=True
)
```

---

## 🤖 AutoGen Integration

Add UAIP to Microsoft AutoGen multi-agent conversations.

### Installation

```bash
pip install uaip pyautogen
```

### Basic Integration

```python
import autogen
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

# Initialize UAIP
uaip_agent = UAIP_Enterprise_SDK(
    agent_name="AutoGenBot",
    company_name="MyCompany",
    secret_code=123456789,
    gateway_url="http://localhost:8000",
    auto_register=True
)

# Custom payment function
def make_secure_payment(recipient: str, amount: float, purpose: str) -> dict:
    """Make a secure payment through UAIP."""
    try:
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE"
        )
        return result
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# Define config with payment capability
config_list = [
    {
        "model": "gpt-4",
        "api_key": "your-openai-key"
    }
]

llm_config = {
    "config_list": config_list,
    "functions": [
        {
            "name": "make_secure_payment",
            "description": "Make a secure payment to another agent with compliance checking",
            "parameters": {
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Recipient's DID (e.g., did:uaip:vendor:abc123)"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Payment amount in USD"
                    },
                    "purpose": {
                        "type": "string",
                        "description": "Payment purpose/description"
                    }
                },
                "required": ["recipient", "amount", "purpose"]
            }
        }
    ]
}

# Create assistant with payment capability
assistant = autogen.AssistantAgent(
    name="FinancialAssistant",
    llm_config=llm_config,
    system_message="You are a financial assistant with secure payment capabilities through UAIP."
)

# Create user proxy
user_proxy = autogen.UserProxyAgent(
    name="UserProxy",
    human_input_mode="NEVER",
    function_map={
        "make_secure_payment": make_secure_payment
    }
)

# Initiate conversation
user_proxy.initiate_chat(
    assistant,
    message="Pay did:uaip:vendor:xyz123 $500 for Q4 consulting services"
)
```

### Multi-Agent Payment Flow

```python
# Finance Agent (approver)
finance_agent = autogen.AssistantAgent(
    name="FinanceManager",
    llm_config=llm_config,
    system_message="You approve or reject payment requests. Approve payments under $1000. Escalate larger amounts."
)

# Procurement Agent (requester)
procurement_agent = autogen.AssistantAgent(
    name="ProcurementAgent",
    llm_config=llm_config,
    system_message="You request payments for vendor invoices. Always include vendor DID and purpose."
)

# Payment Executor (uses UAIP)
payment_executor = autogen.UserProxyAgent(
    name="PaymentExecutor",
    human_input_mode="NEVER",
    function_map={
        "make_secure_payment": make_secure_payment
    }
)

# Group chat
groupchat = autogen.GroupChat(
    agents=[procurement_agent, finance_agent, payment_executor],
    messages=[],
    max_round=10
)

manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=llm_config)

# Start workflow
procurement_agent.initiate_chat(
    manager,
    message="We need to pay vendor did:uaip:vendor:acme $1500 for December cloud services"
)
```

---

## 👥 CrewAI Integration

Add UAIP to CrewAI task-based agents.

### Installation

```bash
pip install uaip crewai crewai-tools
```

### Basic Integration

```python
from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

# Initialize UAIP
uaip_agent = UAIP_Enterprise_SDK(
    agent_name="CrewAIBot",
    company_name="MyCompany",
    secret_code=123456789,
    gateway_url="http://localhost:8000",
    auto_register=True
)

# Create payment tool
@tool("Secure Payment Tool")
def make_payment(recipient_did: str, amount: float, purpose: str) -> str:
    """
    Make a secure payment through UAIP gateway.
    
    Args:
        recipient_did: Recipient's DID (e.g., did:uaip:vendor:abc)
        amount: Payment amount in USD
        purpose: Payment purpose/description
    
    Returns:
        Payment result as string
    """
    try:
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE"
        )
        
        if result['status'] == 'SUCCESS':
            s = result['settlement']
            return f"✅ Payment successful! Amount: ${s['amount']}, Fee: ${s['fee']}, TX: {s['tx_id']}"
        elif result['status'] == 'PENDING_APPROVAL':
            return f"⏸️ Payment pending approval. Request ID: {result['request_id']}"
        else:
            return f"❌ Payment failed: {result}"
            
    except Exception as e:
        return f"❌ Error: {str(e)}"

# Create agents
financial_analyst = Agent(
    role='Financial Analyst',
    goal='Analyze invoices and recommend payments',
    backstory='Expert in financial analysis and vendor management',
    verbose=True,
    allow_delegation=True
)

payment_processor = Agent(
    role='Payment Processor',
    goal='Execute payments securely through UAIP',
    backstory='Specialized in secure transaction processing',
    tools=[make_payment],
    verbose=True,
    allow_delegation=False
)

# Create tasks
analyze_invoice = Task(
    description='Review the vendor invoice for did:uaip:vendor:acme totaling $750 for cloud services',
    agent=financial_analyst,
    expected_output='Invoice analysis with payment recommendation'
)

execute_payment = Task(
    description='Execute the approved payment using the Secure Payment Tool',
    agent=payment_processor,
    expected_output='Payment confirmation with transaction ID'
)

# Create crew
crew = Crew(
    agents=[financial_analyst, payment_processor],
    tasks=[analyze_invoice, execute_payment],
    process=Process.sequential,
    verbose=2
)

# Execute
result = crew.kickoff()
print(result)
```

### Advanced: Financial Workflow Crew

```python
# Define specialized agents
invoice_validator = Agent(
    role='Invoice Validator',
    goal='Validate invoice data and check for errors',
    backstory='Expert in accounts payable and invoice verification',
    verbose=True
)

compliance_checker = Agent(
    role='Compliance Officer',
    goal='Ensure payments comply with company policies',
    backstory='Specialized in financial compliance and risk management',
    verbose=True
)

payment_executor = Agent(
    role='Payment Executor',
    goal='Execute approved payments through UAIP',
    backstory='Handles secure payment execution',
    tools=[make_payment],
    verbose=True
)

# Define workflow tasks
task1 = Task(
    description='Validate invoice from did:uaip:vendor:xyz for $2,500',
    agent=invoice_validator,
    expected_output='Validation report'
)

task2 = Task(
    description='Check compliance for the validated invoice',
    agent=compliance_checker,
    expected_output='Compliance approval or rejection'
)

task3 = Task(
    description='Execute payment if compliance approved',
    agent=payment_executor,
    expected_output='Payment confirmation'
)

# Create crew with sequential process
financial_crew = Crew(
    agents=[invoice_validator, compliance_checker, payment_executor],
    tasks=[task1, task2, task3],
    process=Process.sequential,
    verbose=2
)

# Run workflow
result = financial_crew.kickoff()
```

---

## 🌐 FastAPI Integration

Add UAIP to your FastAPI backend.

### Installation

```bash
pip install uaip fastapi uvicorn
```

### Basic Integration

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

app = FastAPI(title="My App with UAIP")

# Initialize UAIP agent (singleton)
uaip_agent = UAIP_Enterprise_SDK(
    agent_name="MyAppBackend",
    company_name="MyCompany",
    secret_code=123456789,
    gateway_url="http://localhost:8000",
    auto_register=True
)

class PaymentRequest(BaseModel):
    recipient_did: str
    amount: float
    purpose: str
    chain: str = "BASE"

@app.post("/api/payments")
async def create_payment(payment: PaymentRequest):
    """Execute a secure payment through UAIP."""
    try:
        result = uaip_agent.call_agent(
            task=f"Payment: {payment.purpose}",
            amount=Decimal(str(payment.amount)),
            intent=payment.purpose,
            chain=payment.chain
        )
        
        return {
            "success": result['status'] == 'SUCCESS',
            "data": result
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/payments/{request_id}")
async def get_payment_status(request_id: str):
    """Check payment status."""
    # Implement status checking
    return {"request_id": request_id, "status": "PENDING"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

---

## 🔧 Custom Integration Template

For other frameworks, follow this pattern:

```python
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

class MyFrameworkUAIPPlugin:
    """Plugin to add UAIP payments to your framework."""
    
    def __init__(self, agent_name: str, company_name: str, secret_code: int):
        self.uaip = UAIP_Enterprise_SDK(
            agent_name=agent_name,
            company_name=company_name,
            secret_code=secret_code,
            gateway_url="http://localhost:8000",
            auto_register=True
        )
    
    def make_payment(self, recipient: str, amount: float, purpose: str) -> dict:
        """Execute payment with error handling."""
        try:
            result = self.uaip.call_agent(
                task=f"Payment: {purpose}",
                amount=Decimal(str(amount)),
                intent=purpose,
                chain="BASE"
            )
            return result
        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e)
            }
    
    def check_status(self, request_id: str) -> dict:
        """Check payment status."""
        # Implement status polling
        pass

# Usage
plugin = MyFrameworkUAIPPlugin(
    agent_name="MyAgent",
    company_name="MyCompany",
    secret_code=123456789
)

result = plugin.make_payment(
    recipient="did:uaip:vendor:abc",
    amount=100.00,
    purpose="Test payment"
)
```

---

## 📚 Best Practices

### 1. **Secret Management**

```python
import os
from dotenv import load_dotenv

load_dotenv()

uaip_agent = UAIP_Enterprise_SDK(
    agent_name=os.getenv("AGENT_NAME"),
    company_name=os.getenv("COMPANY_NAME"),
    secret_code=int(os.getenv("UAIP_SECRET")),
    gateway_url=os.getenv("GATEWAY_URL", "http://localhost:8000")
)
```

### 2. **Error Handling**

```python
from typing import Dict, Any

def safe_payment(recipient: str, amount: float, purpose: str) -> Dict[str, Any]:
    """Payment with comprehensive error handling."""
    try:
        result = uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE"
        )
        
        return {
            "success": True,
            "data": result
        }
        
    except ValueError as e:
        # Validation errors
        return {
            "success": False,
            "error": "validation",
            "message": str(e)
        }
    
    except RuntimeError as e:
        # Network/gateway errors
        return {
            "success": False,
            "error": "network",
            "message": str(e)
        }
    
    except Exception as e:
        # Unexpected errors
        return {
            "success": False,
            "error": "unknown",
            "message": str(e)
        }
```

### 3. **Async Support**

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=10)

async def async_payment(recipient: str, amount: float, purpose: str):
    """Async wrapper for UAIP payment."""
    loop = asyncio.get_event_loop()
    
    result = await loop.run_in_executor(
        executor,
        lambda: uaip_agent.call_agent(
            task=f"Payment: {purpose}",
            amount=Decimal(str(amount)),
            intent=purpose,
            chain="BASE"
        )
    )
    
    return result

# Usage
result = await async_payment("did:uaip:vendor:abc", 100.00, "Invoice")
```

---

## 🎯 Common Integration Patterns

### Pattern 1: Payment Gateway Service

```python
class PaymentGateway:
    """Centralized payment service for your application."""
    
    def __init__(self):
        self.uaip = UAIP_Enterprise_SDK(...)
        self.cache = {}
    
    def pay(self, recipient: str, amount: float, purpose: str) -> dict:
        # Pre-payment validation
        # Execute payment
        # Post-payment logging
        pass
    
    def get_receipt(self, request_id: str) -> dict:
        # Fetch from cache or UAIP
        pass
```

### Pattern 2: Event-Driven Payments

```python
from typing import Callable

class UAIPEventHandler:
    """Event-driven payment processing."""
    
    def __init__(self):
        self.uaip = UAIP_Enterprise_SDK(...)
        self.listeners = []
    
    def on_payment_success(self, callback: Callable):
        self.listeners.append(("success", callback))
    
    def on_payment_pending(self, callback: Callable):
        self.listeners.append(("pending", callback))
    
    def execute_payment(self, **kwargs):
        result = self.uaip.call_agent(**kwargs)
        
        for event_type, callback in self.listeners:
            if event_type == result['status'].lower():
                callback(result)
        
        return result
```

---

## 🔗 Resources

- [UAIP SDK Documentation](API.md)
- [LangChain Docs](https://python.langchain.com/docs/get_started/introduction)
- [AutoGen Docs](https://microsoft.github.io/autogen/)
- [CrewAI Docs](https://docs.crewai.com/)

---

**Questions?** Open an issue or join our Discord community!