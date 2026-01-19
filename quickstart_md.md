# 🚀 UAIP Quick Start - Get Running in 5 Minutes

> **Goal**: Create your first secure AI agent transaction in under 5 minutes.

---

## ⚡ Fastest Start (Copy-Paste This)

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/uaip-agentguard.git
cd uaip-agentguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set admin key (CRITICAL for security)
export ADMIN_KEY="your-super-secret-admin-key-minimum-32-characters-long"

# 4. Start the gateway (in terminal 1)
python gateway.py

# 5. Run the demo (in terminal 2)
python demo.py
```

**That's it!** 🎉 You should see:
- ✅ Agent registered with cryptographic identity
- ✅ $0.05 nano-transaction approved instantly
- ✅ $5,000 high-value transaction pending approval
- ✅ Dashboard at http://localhost:8000

---

## 📋 Prerequisites

| Requirement | Version | Check Command |
|------------|---------|---------------|
| Python | 3.10+ | `python --version` |
| pip | 20.0+ | `pip --version` |

**That's literally it.** No Docker, no Kubernetes, no blockchain node required for testing.

---

## 🎯 Your First Agent (30 seconds)

Create a file `my_first_agent.py`:

```python
from sdk import UAIP_Enterprise_SDK
from decimal import Decimal

# 1. Create your agent (generates cryptographic identity)
agent = UAIP_Enterprise_SDK(
    agent_name="MyFirstBot",
    company_name="MyCompany",
    secret_code=123456789,  # In production: use secrets.randbelow()
    gateway_url="http://localhost:8000",
    auto_register=True
)

print(f"✅ Agent created: {agent.did}")

# 2. Execute a secure transaction
result = agent.call_agent(
    task="Process test payment",
    amount=Decimal("5.00"),
    intent="Learning UAIP",
    chain="BASE"
)

print(f"✅ Transaction status: {result['status']}")
print(f"💰 Amount: ${result['settlement']['amount']}")
print(f"🏦 Fee: ${result['settlement']['fee']}")
```

Run it:
```bash
python my_first_agent.py
```

**Expected output:**
```
✅ Agent registered: did:uaip:mycompany:a1b2c3d4
✅ Transaction status: SUCCESS
💰 Amount: $5.00
🏦 Fee: $0.01
```

---

## 🏗️ What Just Happened?

### 1. **Identity Created** (Like Getting a Passport)
- Your agent got a **DID** (Decentralized Identifier): `did:uaip:mycompany:a1b2c3d4`
- Generated **Ed25519 keypair** for signing transactions
- Created **Zero-Knowledge commitment** for privacy

### 2. **Gateway Verified Identity** (Like TSA Security)
- Checked cryptographic signature
- Verified ZK-proof (you know the secret without revealing it)
- Prevented replay attacks with nonce

### 3. **Compliance Audit Ran** (Like Legal Review)
- Scanned for prohibited keywords (money laundering, ransomware, etc.)
- Checked amount against EU AI Act thresholds
- Logged to forensic audit trail

### 4. **Settlement Processed** (Like Bank Transfer)
- Calculated tiered fee: $0.01 for transactions <$10
- Simulated USDC transfer on Base blockchain
- Generated immutable receipt

---

## 📊 Understanding the Dashboard

Open http://localhost:8000 in your browser:

![Dashboard Preview](https://via.placeholder.com/800x400/1a1f2e/58a6ff?text=AgentGuard+Dashboard)

### What You See:

| Column | Meaning |
|--------|---------|
| **Agent DID** | Who initiated the transaction |
| **Intent** | Human-readable purpose |
| **Value** | USD amount |
| **Status** | `ALLOW` (auto-approved), `PENDING` (needs human), `BLOCKED` (compliance violation) |
| **Legal Grounding** | Which law/regulation applies (EU AI Act, SOC2, etc.) |
| **Action** | Approve/Reject buttons for pending transactions |

### Approving High-Value Transactions:

1. Run a high-value transaction:
   ```python
   agent.call_agent(
       task="Enterprise payment",
       amount=Decimal("5000.00"),
       intent="Requires CFO approval",
       chain="BASE"
   )
   ```

2. Go to dashboard at http://localhost:8000
3. Find the pending transaction (orange row)
4. Click **Approve** button
5. Enter admin key when prompted: `your-super-secret-admin-key-minimum-32-characters-long`
6. Transaction completes!

---

## 🔐 Security Features You Get For Free

✅ **Ed25519 Digital Signatures** - Every request cryptographically signed  
✅ **Zero-Knowledge Proofs** - Prove identity without revealing secrets  
✅ **Replay Attack Prevention** - Nonce + timestamp validation  
✅ **Rate Limiting** - 100 requests/minute per IP  
✅ **SQL Injection Protection** - Parameterized queries + validation  
✅ **XSS Prevention** - HTML escaping on all outputs  
✅ **Timing Attack Resistance** - Constant-time comparisons  
✅ **Compliance Auditing** - EU AI Act, SOC2, GDPR checks  
✅ **Forensic Logging** - Immutable audit trails  

**You don't write a single line of security code. It's all built-in.**

---

## 🎓 Next Steps

### Beginner:
1. Read [ARCHITECTURE.md](ARCHITECTURE.md) - Visual diagrams
2. Run examples:
   - `python examples/01_hello_world.py`
   - `python examples/02_agent_to_agent.py`

### Intermediate:
1. Read [API.md](API.md) - Complete endpoint reference
2. Integrate with your existing Python app
3. Customize compliance rules in `compliance.py`

### Advanced:
1. Deploy with Docker: `docker-compose up`
2. Integrate with LangChain: See [INTEGRATIONS.md](INTEGRATIONS.md)
3. Add custom chains in `settlement.py`

---

## 🆘 Troubleshooting

### ❌ "ModuleNotFoundError: No module named 'nacl'"
```bash
pip install PyNaCl
```

### ❌ "ADMIN_KEY must be set with minimum 32 characters"
```bash
export ADMIN_KEY="this-is-my-very-secure-admin-key-1234567890"
```

### ❌ "Cannot connect to gateway"
Make sure `gateway.py` is running:
```bash
# Terminal 1
python gateway.py

# Terminal 2 (in another window)
python demo.py
```

### ❌ "Port 8000 already in use"
Change the port in `gateway.py` (line 474):
```python
uvicorn.run(app, host="0.0.0.0", port=8001)
```

---

## 💬 Getting Help

- **Found a bug?** Open an issue: [GitHub Issues](https://github.com/yourusername/uaip-agentguard/issues)
- **Have a question?** Ask in [Discussions](https://github.com/yourusername/uaip-agentguard/discussions)
- **Want to contribute?** Read [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🎉 Success Checklist

After running the quick start, you should have:

- [ ] Gateway running at http://localhost:8000
- [ ] Demo executed successfully
- [ ] Saw transactions in the dashboard
- [ ] Created your first agent in Python
- [ ] Processed a test transaction

**Congratulations!** You're now running a production-grade secure settlement layer for AI agents. 🚀

---

**Next**: Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand how it all works under the hood.