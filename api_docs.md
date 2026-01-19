# 📡 UAIP Gateway API Reference

Complete documentation for all API endpoints, request/response formats, and error codes.

---

## 🔐 Authentication

All requests (except `/health` and dashboard `/`) require:
1. **Ed25519 Signature** - Cryptographic proof of request authenticity
2. **Zero-Knowledge Proof** - Privacy-preserving identity verification
3. **Nonce** - Unique identifier to prevent replay attacks
4. **Timestamp** - Request freshness validation (±30 seconds)

---

## 📋 Endpoints Overview

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/` | GET | Admin dashboard (HTML) | No |
| `/health` | GET | Health check | No |
| `/v1/register` | POST | Register new agent | Signature only |
| `/v1/execute` | POST | Execute transaction | Full auth |
| `/v1/decision/{req_id}/{choice}` | POST | Approve/deny pending | Admin key |
| `/v1/check/{req_id}` | GET | Check transaction status | No |

---

## 1️⃣ Agent Registration

### `POST /v1/register`

Register a new agent with cryptographic identity.

#### Request Body

```json
{
  "registration_data": {
    "agent_id": "did:uaip:company:abc123",
    "zk_commitment": "12345678901234567890",
    "public_key": "a1b2c3d4...",
    "timestamp": 1705680000.0
  },
  "signature": "e5f6g7h8...",
  "public_key": "a1b2c3d4..."
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `registration_data.agent_id` | string | ✅ | DID (Decentralized Identifier) |
| `registration_data.zk_commitment` | string | ✅ | Zero-knowledge commitment (integer as string) |
| `registration_data.public_key` | string | ✅ | Ed25519 public key (hex-encoded) |
| `registration_data.timestamp` | float | ✅ | Unix timestamp |
| `signature` | string | ✅ | Ed25519 signature of registration_data (hex) |
| `public_key` | string | ✅ | Same as registration_data.public_key |

#### Response (Success)

```json
{
  "status": "REGISTERED",
  "agent_id": "did:uaip:company:abc123"
}
```

#### Response Codes

| Code | Meaning |
|------|---------|
| `200` | Registration successful |
| `400` | Invalid request (missing fields, bad format) |
| `401` | Signature verification failed |
| `429` | Rate limit exceeded (max 10 registrations/minute per IP) |
| `500` | Server error |

#### Example (Python SDK)

```python
from sdk import UAIP_Enterprise_SDK

agent = UAIP_Enterprise_SDK(
    agent_name="MyBot",
    company_name="MyCo",
    secret_code=123456789,
    gateway_url="http://localhost:8000",
    auto_register=True  # Automatically calls /v1/register
)
```

#### Example (cURL)

```bash
curl -X POST http://localhost:8000/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "registration_data": {
      "agent_id": "did:uaip:test:12345",
      "zk_commitment": "987654321",
      "public_key": "abcd1234",
      "timestamp": 1705680000.0
    },
    "signature": "ef5678...",
    "public_key": "abcd1234"
  }'
```

---

## 2️⃣ Execute Transaction

### `POST /v1/execute`

Execute a governed transaction with compliance checking and settlement.

#### Request Body

```json
{
  "sender_id": "did:uaip:company:abc123",
  "task": "Process vendor payment",
  "amount": "150.00",
  "chain": "BASE",
  "intent": "Q1 2024 vendor invoice #12345",
  "data": {
    "task": "Process vendor payment",
    "amount": "150.00",
    "intent": "Q1 2024 vendor invoice #12345",
    "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": 1705680000.0
  },
  "signature": "e5f6g7h8...",
  "public_key": "a1b2c3d4...",
  "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": 1705680000.0,
  "zk_proof": {
    "r": "123456789...",
    "s": "987654321...",
    "timestamp": 1705680000
  }
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sender_id` | string | ✅ | Agent DID |
| `task` | string | ✅ | Task description (3-5000 chars) |
| `amount` | string | ✅ | USD amount (0.01-1,000,000,000) |
| `chain` | string | ✅ | Blockchain: BASE, SOLANA, ETHEREUM, POLYGON |
| `intent` | string | ✅ | Human-readable purpose (3-2000 chars) |
| `data` | object | ✅ | Transaction data (will be signed) |
| `signature` | string | ✅ | Ed25519 signature of `data` field (hex) |
| `public_key` | string | ✅ | Ed25519 public key (hex) |
| `nonce` | string | ✅ | Unique UUID (prevents replay attacks) |
| `timestamp` | float | ✅ | Unix timestamp (within ±30 seconds) |
| `zk_proof` | object | ✅ | Zero-knowledge proof |
| `zk_proof.r` | string | ✅ | ZK proof commitment |
| `zk_proof.s` | string | ✅ | ZK proof response |
| `zk_proof.timestamp` | int | ✅ | Proof creation time |

#### Response (Instant Approval - Amount < $1,000)

```json
{
  "status": "SUCCESS",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "settlement": {
    "status": "SUCCESS",
    "tx_id": "uaip_tx_abcd1234ef567890",
    "amount": 150.0,
    "fee": 1.5,
    "payout": 148.5,
    "fee_percentage": 1.0,
    "tier": "B",
    "chain": "BASE",
    "currency": "USDC",
    "timestamp": 1705680000.0,
    "processing_time_ms": 45.23
  }
}
```

#### Response (Pending Human Approval - Amount >= $1,000)

```json
{
  "status": "PENDING_APPROVAL",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "message": "High-value transaction requires human approval"
}
```

#### Response (Compliance Violation)

```json
{
  "detail": {
    "error": "COMPLIANCE_VIOLATION",
    "audit": {
      "audit_id": "AUDIT-ABC12345",
      "timestamp": "2024-01-19T10:30:00Z",
      "status": "TERMINATE",
      "verification_reasoning": "HARD_RULE_OVERRIDE: Prohibited keyword detected: 'offshore'",
      "grounded_law": "AML/KYC Regulations (FATF Recommendations 10-16)",
      "disclaimer": "LEGAL DISCLAIMER: AI-generated audit..."
    }
  }
}
```

#### Response Codes

| Code | Meaning |
|------|---------|
| `200` | Transaction successful or pending |
| `400` | Invalid request (validation failed) |
| `401` | Authentication failed (signature/ZK proof invalid) |
| `403` | Forbidden (replay attack, blacklisted agent) |
| `429` | Rate limit exceeded (100 requests/minute) |
| `451` | Compliance violation (transaction blocked) |
| `500` | Server error |

#### Fee Structure

| Tier | Condition | Fee |
|------|-----------|-----|
| **Tier A** | Amount ≤ $10 | **$0.01 flat** |
| **Tier B** | $10 < Amount ≤ $10,000 | **1.0% of amount** |
| **Tier C** | Amount > $10,000 | **$10 + 0.5% of amount** |

#### Example (Python SDK)

```python
result = agent.call_agent(
    task="Process vendor invoice #12345",
    amount=150.00,
    intent="Q1 2024 vendor payments",
    chain="BASE"
)

if result['status'] == 'SUCCESS':
    print(f"✅ Paid: ${result['settlement']['amount']}")
    print(f"🏦 Fee: ${result['settlement']['fee']}")
elif result['status'] == 'PENDING_APPROVAL':
    print(f"⏸️  Awaiting approval: {result['request_id']}")
```

---

## 3️⃣ Manual Decision (Admin Only)

### `POST /v1/decision/{req_id}/{choice}`

Approve or deny a pending high-value transaction.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `req_id` | UUID | Transaction request ID |
| `choice` | string | `allow` or `deny` |

#### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Admin-Key` | ✅ | Admin key from environment variable `ADMIN_KEY` |

#### Response (Approval)

```json
{
  "status": "SETTLED",
  "settlement": {
    "status": "SUCCESS",
    "tx_id": "uaip_tx_abcd1234",
    "amount": 5000.0,
    "fee": 35.0,
    "payout": 4965.0,
    "tier": "C",
    "chain": "BASE"
  }
}
```

#### Response (Denial)

```json
{
  "status": "REJECTED"
}
```

#### Response Codes

| Code | Meaning |
|------|---------|
| `200` | Decision processed |
| `401` | Invalid admin key |
| `404` | Transaction not found or already processed |
| `500` | Server error |

#### Example (cURL)

```bash
curl -X POST http://localhost:8000/v1/decision/a1b2c3d4-e5f6-7890-abcd-ef1234567890/allow \
  -H "X-Admin-Key: your-admin-key-here"
```

#### Example (Dashboard)

1. Go to http://localhost:8000
2. Find pending transaction (orange row)
3. Click **Approve** button
4. Enter admin key when prompted
5. Transaction completes instantly

---

## 4️⃣ Check Transaction Status

### `GET /v1/check/{req_id}`

Check the status of a pending or completed transaction.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `req_id` | UUID | Transaction request ID |

#### Response

```json
{
  "status": "WAITING",  // or APPROVED, REJECTED, NOT_FOUND
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

#### Response Codes

| Code | Meaning |
|------|---------|
| `200` | Status retrieved |
| `500` | Server error |

#### Example (Python SDK with Polling)

```python
result = agent.call_agent(
    task="High-value payment",
    amount=5000.00,
    intent="Needs approval",
    chain="BASE",
    wait_for_approval=True  # SDK polls automatically
)

# SDK polls /v1/check/{req_id} every 2 seconds
# Returns when status changes to APPROVED or REJECTED
```

#### Example (Manual Polling)

```bash
# Check status
curl http://localhost:8000/v1/check/a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Response: {"status": "WAITING", "request_id": "..."}
```

---

## 5️⃣ Health Check

### `GET /health`

Check if the gateway is operational.

#### Response

```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

#### Response Codes

| Code | Meaning |
|------|---------|
| `200` | Service healthy |
| `503` | Service unhealthy (database connection failed) |

#### Example

```bash
curl http://localhost:8000/health
```

---

## 6️⃣ Admin Dashboard

### `GET /`

Web-based dashboard for monitoring and approving transactions.

#### Features

- Real-time transaction monitoring
- Manual approval/rejection workflow
- Statistics dashboard
- Forensic audit trail viewer

#### Access

Open http://localhost:8000 in any modern browser.

#### Authentication

No authentication required for viewing. Admin key required for approvals.

---

## ⚠️ Error Codes Reference

### HTTP Status Codes

| Code | Name | Meaning |
|------|------|---------|
| `200` | OK | Request successful |
| `400` | Bad Request | Validation failed (check error message) |
| `401` | Unauthorized | Authentication failed |
| `403` | Forbidden | Request blocked (replay attack, blacklist, etc.) |
| `404` | Not Found | Resource not found |
| `429` | Too Many Requests | Rate limit exceeded |
| `451` | Unavailable For Legal Reasons | Compliance violation |
| `500` | Internal Server Error | Server error (check logs) |
| `503` | Service Unavailable | Service unhealthy |

### Error Response Format

```json
{
  "detail": "Human-readable error message"
}
```

Or for compliance violations:

```json
{
  "detail": {
    "error": "COMPLIANCE_VIOLATION",
    "audit": {
      "audit_id": "AUDIT-...",
      "status": "TERMINATE",
      "verification_reasoning": "...",
      "grounded_law": "..."
    }
  }
}
```

---

## 🔒 Security Best Practices

### 1. Never Commit Secrets

```bash
# Add to .gitignore
.env
*.db
*.log
uaip_vault.db
uaip_forensic_records.json
uaip_settlements.jsonl
```

### 2. Rotate Admin Keys

```python
# Generate new admin key
import secrets
print(secrets.token_urlsafe(48))
```

### 3. Monitor Rate Limits

```python
# SDK automatically handles rate limits with exponential backoff
# No action needed from developers
```

### 4. Validate Responses

```python
result = agent.call_agent(...)

if result.get('status') == 'SUCCESS':
    # Verify settlement
    assert 'settlement' in result
    assert 'tx_id' in result['settlement']
elif result.get('status') == 'PENDING_APPROVAL':
    # Handle approval workflow
    print(f"Pending: {result['request_id']}")
else:
    # Handle errors
    print(f"Error: {result}")
```

---

## 📚 Additional Resources

- [QUICKSTART.md](QUICKSTART.md) - Get running in 5 minutes
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design and diagrams
- [INTEGRATIONS.md](INTEGRATIONS.md) - LangChain, AutoGen, CrewAI guides
- [Examples](examples/) - Code examples for common use cases

---

**Questions?** Open an issue on GitHub or join our Discord community.