# 🛡️ UAIP + AgentGuard

**The Secure Settlement & Interoperability Layer for the Autonomous AI Economy**

[![License: FSL-1.1-Apache-2.0](https://img.shields.io/badge/License-FSL--1.1--Apache--2.0-blue.svg)](https://fsl.software/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security: Zero-Trust](https://img.shields.io/badge/Security-Zero--Trust-red.svg)]()
[![Compliance: EU-AI-ACT-Ready](https://img.shields.io/badge/Compliance-EU--AI--ACT--Ready-orange.svg)]()

> **Imagine if AI agents could safely transact with each other across companies, with built-in legal compliance and military-grade security.**
> 
> That's UAIP. The "TCP/IP for AI agents" with a security-first approach.

---
## 📁 Repository Structure
```
UAIP-Protocol/
├── 📚 docs/          → Complete documentation (guides, PDFs)
├── 🐍 uaip/          → Core Python source code
├── 📝 examples/      → Working integration examples
├── 🐳 deployment/    → Docker & deployment files
└── .github/          → CI/CD workflows
```

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Clone and install
git clone https://github.com/yourusername/uaip-agentguard.git
cd uaip-agentguard
pip install -r requirements.txt

# 2. Set admin key (CRITICAL!)
export ADMIN_KEY="your-super-secret-admin-key-minimum-32-characters-long"

# 3. Start gateway
python gateway.py

# 4. Run demo (in another terminal)
python demo.py
```

**Done!** 🎉 Open http://localhost:8000 to see your dashboard.

👉 **New to UAIP?** Read [QUICKSTART.md](QUICKSTART.md) for detailed setup.

---

## 🎯 What Problem Does This Solve?

### The Challenge

AI agents from different companies (OpenAI, Microsoft, Anthropic) can't safely transact because:

- ❌ No standard identity system
- ❌ No compliance framework (agents could break laws)
- ❌ No secure payment rails
- ❌ No audit trails for regulators
- ❌ No human oversight for high-risk actions

### The Solution: UAIP

✅ **Cryptographic Identity** - Every agent has an unfakeable DID (Decentralized Identifier)  
✅ **AI-Powered Compliance** - Real-time legal checks (EU AI Act, SOC2, GDPR)  
✅ **Zero-Knowledge Privacy** - Prove identity without revealing secrets  
✅ **Multi-Chain Settlement** - USDC payments on Base, Solana, Ethereum, Polygon  
✅ **Human-in-the-Loop** - High-value transactions require approval  
✅ **Forensic Audit Trails** - Every action logged for regulators  

---

## ✨ Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| 🔐 **Ed25519 Signatures** | Every request cryptographically signed | Prevents impersonation attacks |
| 🕵️ **Zero-Knowledge Proofs** | Schnorr protocol for privacy | Authenticate without exposing secrets |
| ⚖️ **RAG Compliance** | Llama-3-Legal audits every transaction | Avoid $100M+ AI Act fines |
| 💰 **Tiered Fees** | 0.5%-1% depending on amount | Fair pricing: $0.01 for nano-tasks |
| 🚨 **Keyword Blocking** | Auto-blocks money laundering terms | Stay on right side of law |
| 👤 **Human Oversight** | Dashboard for manual approvals | EU AI Act Article 14 compliant |
| 📊 **Multi-Chain** | Base, Solana, Ethereum, Polygon | Use your preferred network |
| 🔄 **Idempotency** | Prevent duplicate payments | Financial safety guaranteed |

---

## 🏗️ Architecture (Visual Overview)

```
┌─────────────────────────────────────────────────────────────┐
│                   AI Agent Ecosystem                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ OpenAI   │  │Microsoft │  │Anthropic │  │ Custom   │   │
│  │ Agent    │  │  Agent   │  │  Agent   │  │  Agent   │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │              │             │          │
│       └─────────────┴──────────────┴─────────────┘          │
│                            │                                │
│                    ┌───────▼────────┐                       │
│                    │   UAIP SDK     │ ◄── You are here!    │
│                    │  (Python)      │                       │
│                    └───────┬────────┘                       │
└────────────────────────────┼──────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  UAIP Gateway   │ ◄── Central Hub
                    │  (FastAPI)      │
                    └────┬────┬───┬───┘
                         │    │   │
          ┌──────────────┘    │   └──────────────┐
          │                   │                  │
   ┌──────▼──────┐   ┌────────▼────────┐   ┌────▼──────┐
   │ Compliance  │   │   Settlement    │   │  Privacy  │
   │  Auditor    │   │     Engine      │   │   (ZK)    │
   │  (AI RAG)   │   │  (Multi-chain)  │   │           │
   └─────────────┘   └─────────────────┘   └───────────┘
```

📖 **Detailed diagrams**: See [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 📝 Your First Agent (30 Seconds)

```python
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

# 1. Create agent (auto-registers with gateway)
agent = UAIP_Enterprise_SDK(
    agent_name="FinanceBot",
    company_name="Acme Corp",
    secret_code=123456789,  # Keep this SECRET!
    gateway_url="http://localhost:8000"
)

print(f"✅ Agent DID: {agent.did}")

# 2. Make a secure payment
result = agent.call_agent(
    task="Process vendor invoice",
    amount=Decimal("150.00"),
    intent="Q1 2024 payment to vendor",
    chain="BASE"
)

print(f"✅ Status: {result['status']}")
print(f"💰 Amount: ${result['settlement']['amount']}")
print(f"🏦 Fee: ${result['settlement']['fee']}")
```

**Output:**
```
✅ Agent DID: did:uaip:acmecorp:a1b2c3d4
✅ Status: SUCCESS
💰 Amount: $150.00
🏦 Fee: $1.50
```

---

## 🔒 Security Guarantees

### What You Get Automatically

| Security Feature | How It Works | Attack Prevented |
|-----------------|--------------|------------------|
| **Ed25519 Signing** | Every request signed with private key | Impersonation, MitM attacks |
| **Nonce Tracking** | UUID per request, checked for reuse | Replay attacks |
| **Timestamp Validation** | Requests must be ±30s of server time | Delayed replay attacks |
| **Rate Limiting** | 100 req/min per IP, exponential backoff | DoS attacks |
| **IP Lockout** | 5 failed attempts = 5 min lockout | Brute force attacks |
| **SQL Injection Protection** | Parameterized queries only | Database injection |
| **XSS Prevention** | HTML escaping on all outputs | Cross-site scripting |
| **ZK Proofs** | Schnorr protocol, 128-bit security | Secret exposure |
| **Decimal Precision** | Never use floats for money | Rounding errors |

### Compliance Coverage

✅ **EU AI Act** - High-risk AI system requirements (Article 14: Human oversight)  
✅ **SOC2** - Continuous monitoring, audit trails (CC7.2)  
✅ **GDPR** - Right to human review of automated decisions (Article 22)  
✅ **PCI-DSS** - Automated audit trails (10.2)  
✅ **AML/KYC** - FATF Recommendations 10-16 keyword blocking  

---

## 🎓 Documentation

| Document | Purpose | Read If... |
|----------|---------|-----------|
| [QUICKSTART.md](QUICKSTART.md) | Get running in 5 minutes | You're brand new |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Visual system design | You want to understand internals |
| [API.md](API.md) | Complete endpoint reference | You're integrating directly |
| [INTEGRATIONS.md](INTEGRATIONS.md) | LangChain, AutoGen, CrewAI | You use existing frameworks |
| [examples/](examples/) | Code examples | You learn by doing |

---

## 🔌 Framework Integrations

### LangChain

```python
from langchain.agents import Tool
from sdk import UAIP_Enterprise_SDK

uaip = UAIP_Enterprise_SDK(...)

payment_tool = Tool(
    name="SecurePayment",
    func=lambda x: uaip.call_agent(...),
    description="Make secure payments"
)

# Use in your LangChain agent
agent = initialize_agent(tools=[payment_tool], ...)
```

### AutoGen

```python
from sdk import UAIP_Enterprise_SDK

uaip = UAIP_Enterprise_SDK(...)

# Add as function to AutoGen agent
llm_config = {
    "functions": [
        {
            "name": "make_payment",
            "description": "Secure payment via UAIP",
            ...
        }
    ]
}
```

### CrewAI

```python
from crewai_tools import tool
from sdk import UAIP_Enterprise_SDK

uaip = UAIP_Enterprise_SDK(...)

@tool("Secure Payment")
def make_payment(recipient, amount, purpose):
    return uaip.call_agent(...)

# Use in CrewAI agent
agent = Agent(tools=[make_payment], ...)
```

👉 **Full guides**: See [INTEGRATIONS.md](INTEGRATIONS.md)

---

## 🐳 Docker Deployment

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env and set ADMIN_KEY

# 3. Start with Docker Compose
docker-compose up -d

# 4. Check logs
docker-compose logs -f gateway
```

Access dashboard at http://localhost:8000

---

## 📊 How It Works (Step-by-Step)

### 1. Agent Registers
```
Agent → Gateway: "Here's my public key and ZK commitment"
Gateway: Verifies signature, stores identity → Returns DID
```

### 2. Agent Makes Payment
```
Agent → Gateway: Signed transaction + ZK proof
Gateway: ✓ Signature valid?
         ✓ ZK proof valid?
         ✓ Nonce not reused?
         ✓ Not on blacklist?
```

### 3. Compliance Check
```
Compliance Auditor: ✓ No prohibited keywords?
                    ✓ Amount < $1000 (auto-approve)?
                    ✓ EU AI Act compliant?
```

### 4. Settlement
```
If approved → Financial Engine: Calculate fee
                               → Simulate USDC transfer
                               → Log to audit trail
                               → Return receipt

If needs approval → Store in pending table
                   → Human reviews in dashboard
                   → Approves/denies
```

---

## 🎯 Use Cases

### 1. Autonomous Procurement

```python
# Supply chain agent pays vendor automatically
procurement_agent.call_agent(
    task="Purchase cloud credits",
    amount=Decimal("500.00"),
    intent="AWS credits for Q1",
    chain="BASE"
)
```

### 2. Multi-Company AI Workflows

```python
# Company A's agent pays Company B's agent for service
result = companyA_agent.call_agent(
    task="Data analysis service",
    amount=Decimal("2500.00"),
    intent="Market research report",
    chain="SOLANA"
)
```

### 3. Bounty/Task Markets

```python
# Platform agent distributes bounties to worker agents
for worker in completed_tasks:
    platform_agent.call_agent(
        task=f"Bounty: {worker.task_id}",
        amount=worker.reward,
        intent=f"Completed: {worker.description}",
        chain="BASE"
    )
```

---

## 🛠️ Development

### Run Tests

```bash
# Unit tests
pytest tests/

# Integration tests
pytest tests/integration/

# E2E tests (requires gateway running)
python tests/e2e/test_full_workflow.py
```

### Code Quality

```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy .
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code style guidelines
- Pull request process
- Testing requirements
- Community guidelines

---

## 📜 License

This project is licensed under the **Functional Source License (FSL) 1.1**.

### TL;DR

| Use Case | License |
|----------|---------|
| Personal projects | ✅ Free & Open Source |
| Internal business use | ✅ Free & Open Source |
| Research & education | ✅ Free & Open Source |
| Commercial managed services | ⚠️ Requires commercial license |

After 2 years (Jan 2028), this automatically becomes Apache 2.0.

See [LICENSE](LICENSE) for full details.

---

## 🌟 Why UAIP?

### Traditional Approach (Risky)
```python
# Agent calls payment API directly
response = requests.post(
    "https://payment-api.com/charge",
    json={"amount": 1000000}  # Whoops, $1M transaction!
)
# ❌ No compliance check
# ❌ No human oversight
# ❌ No audit trail
# ❌ Can't prove who sent it
```

### UAIP Approach (Secure)
```python
# Agent uses UAIP
result = agent.call_agent(
    task="Important payment",
    amount=Decimal("1000000.00"),
    intent="Needs CFO approval",
    chain="BASE"
)
# ✅ Cryptographic identity verified
# ✅ Compliance automatically checked
# ✅ Human approval required (EU AI Act compliant)
# ✅ Complete audit trail for regulators
# ✅ Multi-chain settlement
```

---

## 📞 Support

- 🐛 **Bug reports**: [GitHub Issues](https://github.com/jahanzaibahmad112-dotom/UAIP-Protocol/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/jahanzaibahmad112-dotom/UAIP-Protocol/discussions)
- 📧 **Email**: uaip.protocol@gmail.com
- 💼 **Enterprise**: uaip.protocol@gmail.com

---

## 🗺️ Roadmap

### Q1 2026 (Current)
- [x] Core security layer
- [x] Python SDK
- [x] Multi-chain support (Base, Solana)
- [ ] LangChain integration
- [ ] AutoGen integration

### Q2 2026
- [ ] JavaScript/TypeScript SDK
- [ ] Rust SDK for high-performance applications
- [ ] Real blockchain integration (currently simulated)
- [ ] Advanced dashboard with analytics

### Q3 2026
- [ ] Agent marketplace
- [ ] Decentralized governance
- [ ] Cross-chain bridges
- [ ] Mobile SDK

---

## 🙏 Acknowledgments

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [PyNaCl](https://pynacl.readthedocs.io/) - Ed25519 cryptography
- [SQLite](https://www.sqlite.org/) - Lightweight database
- [Uvicorn](https://www.uvicorn.org/) - ASGI server

Inspired by:
- W3C DID Specification
- Schnorr Signature Protocol
- EU AI Act Article 14 (Human Oversight)
- FATF AML/KYC Guidelines

---

## ⭐ Star History

If you find UAIP useful, please star the repo! It helps us grow.

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/uaip-agentguard&type=Date)](https://star-history.com/#yourusername/uaip-agentguard&Date)

---

<div align="center">

**🛡️ UAIP: Building the Secure Highway for the Autonomous Economy**

[Website](https://uaip.io) • [Documentation](https://docs.uaip.io) • [Discord](https://discord.gg/uaip) • [Twitter](https://twitter.com/uaip_protocol)

</div>
