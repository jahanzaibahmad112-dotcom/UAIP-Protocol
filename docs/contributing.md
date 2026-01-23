# 🤝 Contributing to UAIP

Thank you for your interest in contributing to UAIP! We welcome contributions from everyone.

---

## 📋 Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [How to Contribute](#how-to-contribute)
5. [Code Guidelines](#code-guidelines)
6. [Testing](#testing)
7. [Pull Request Process](#pull-request-process)
8. [Community](#community)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, gender, gender identity, sexual orientation, disability, personal appearance, race, ethnicity, age, religion, or nationality.

### Our Standards

**Examples of encouraged behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Examples of unacceptable behavior:**
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at uaip.protocol@gmail.com. All complaints will be reviewed and investigated promptly and fairly.

---

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:

- **Python 3.10+** installed
- **Git** for version control
- **GitHub account** for submitting pull requests
- Basic understanding of:
  - Python programming
  - Cryptography concepts (helpful but not required)
  - REST APIs

### First-Time Contributors

New to open source? Here are some great first issues:

1. Look for issues labeled `good first issue`
2. Read the [QUICKSTART.md](QUICKSTART.md) guide
3. Join our Discord community for help
4. Start small - fix typos, improve docs, add tests

---

## 💻 Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/UAIP-Protocol.git
cd UAIP-Protocol

# Add upstream remote
git remote add upstream https://github.com/jahanzaibahmad112-dotcom/UAIP-Protocol.git
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If exists

# Install in editable mode
pip install -e .
```

### 4. Set Up Environment Variables

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and set:
# - ADMIN_KEY (generate with: python -c "import secrets; print(secrets.token_urlsafe(48))")
# - Other required variables
```

### 5. Run Tests

```bash
# Run test suite
pytest tests/

# Run with coverage
pytest --cov=. tests/

# Run specific test file
pytest tests/test_sdk.py
```

### 6. Start Development Server

```bash
# Start gateway
python gateway.py

# In another terminal, run demo
python demo.py
```

---

## 🔧 How to Contribute

### Reporting Bugs

**Before submitting a bug report:**
- Check existing issues to avoid duplicates
- Update to the latest version and test again
- Collect relevant information (error messages, logs, etc.)

**When submitting a bug report, include:**

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run '...'
2. Call endpoint '....'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
 - OS: [e.g., macOS 14.1]
 - Python version: [e.g., 3.11.5]
 - UAIP version: [e.g., 1.0.0]

**Additional context**
Error logs, screenshots, etc.
```

### Suggesting Enhancements

**Before submitting an enhancement:**
- Check if it's already been suggested
- Make sure it aligns with project goals
- Consider if it would benefit most users

**When suggesting an enhancement:**

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
Clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Additional context**
Why this would be valuable, use cases, etc.
```

### Adding Documentation

Documentation is highly valued! You can contribute by:

- Fixing typos or clarifying existing docs
- Adding examples to the `examples/` directory
- Writing tutorials or how-to guides
- Improving API documentation
- Translating documentation (future)

### Writing Code

We welcome code contributions! Here's how:

1. **Find or create an issue** - Discuss your idea first
2. **Create a branch** - Use descriptive names
3. **Write code** - Follow our style guide
4. **Add tests** - Maintain or improve coverage
5. **Update docs** - Document new features
6. **Submit PR** - Follow our PR template

---

## 📝 Code Guidelines

### Python Style Guide

We follow **PEP 8** with some modifications:

```python
# Good: Descriptive names, type hints, docstrings
def process_payment(
    amount: Decimal,
    recipient: str,
    purpose: str
) -> Dict[str, Any]:
    """
    Process a payment transaction.
    
    Args:
        amount: Payment amount in USD
        recipient: Recipient's DID
        purpose: Payment purpose
        
    Returns:
        Transaction result dictionary
        
    Raises:
        ValueError: If amount is invalid
    """
    if amount <= 0:
        raise ValueError("Amount must be positive")
    
    # Implementation...
    return result

# Bad: No types, no docstring, unclear names
def pay(a, r, p):
    if a <= 0:
        raise Exception("bad")
    return do_thing(a, r, p)
```

### Code Style Rules

**Formatting:**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use `black` for automatic formatting: `black .`
- Use `flake8` for linting: `flake8 .`

**Imports:**
```python
# Standard library
import os
import sys
from typing import Dict, Any

# Third-party
from decimal import Decimal
import nacl.signing

# Local imports
from sdk import UAIP_Enterprise_SDK
from compliance import ComplianceAuditor
```

**Type Hints:**
```python
# Always use type hints
def calculate_fee(amount: Decimal) -> Tuple[Decimal, str]:
    ...

# For complex types
from typing import Optional, Dict, List
def get_stats() -> Optional[Dict[str, Any]]:
    ...
```

**Docstrings:**
```python
# Use Google-style docstrings
def example_function(param1: str, param2: int) -> bool:
    """
    One-line summary of what the function does.
    
    More detailed explanation if needed. Can span multiple lines
    and include examples.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When param1 is empty
        RuntimeError: When operation fails
        
    Example:
        >>> result = example_function("test", 42)
        >>> print(result)
        True
    """
    ...
```

### Security Guidelines

**Critical: Never commit secrets!**

```python
# ❌ BAD - Hardcoded secrets
ADMIN_KEY = "my-secret-key-12345"

# ✅ GOOD - Use environment variables
ADMIN_KEY = os.getenv("ADMIN_KEY")
if not ADMIN_KEY:
    raise ValueError("ADMIN_KEY must be set")
```

**Always validate inputs:**

```python
# ❌ BAD - No validation
def transfer(amount):
    return send_money(amount)

# ✅ GOOD - Comprehensive validation
def transfer(amount: Any) -> Dict[str, Any]:
    """Transfer money with validation."""
    try:
        amount_dec = Decimal(str(amount))
    except (ValueError, InvalidOperation):
        raise ValueError(f"Invalid amount: {amount}")
    
    if amount_dec <= 0:
        raise ValueError("Amount must be positive")
    
    if amount_dec > MAX_AMOUNT:
        raise ValueError(f"Amount exceeds maximum: {MAX_AMOUNT}")
    
    return send_money(amount_dec)
```

**Use parameterized SQL:**

```python
# ❌ BAD - SQL injection vulnerability
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# ✅ GOOD - Parameterized query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

---

## 🧪 Testing

### Writing Tests

We use `pytest` for testing. All new code should include tests.

**Test file structure:**
```
tests/
├── __init__.py
├── test_sdk.py           # SDK tests
├── test_gateway.py       # Gateway tests
├── test_compliance.py    # Compliance tests
├── test_settlement.py    # Settlement tests
├── test_privacy.py       # Privacy/ZK tests
└── integration/
    └── test_full_workflow.py
```

**Example test:**
```python
# tests/test_sdk.py
import pytest
from decimal import Decimal
from sdk import UAIP_Enterprise_SDK

def test_agent_registration():
    """Test agent can register successfully."""
    agent = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        gateway_url="http://localhost:8000",
        auto_register=False  # Don't call real gateway in tests
    )
    
    assert agent.did.startswith("did:uaip:")
    assert agent.pk is not None
    assert agent.zk_commitment > 0


def test_amount_validation():
    """Test amount validation catches invalid inputs."""
    agent = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        auto_register=False
    )
    
    # Should raise ValueError for negative amount
    with pytest.raises(ValueError, match="Amount cannot be negative"):
        agent._validate_amount(Decimal("-100"))
    
    # Should raise ValueError for amount exceeding max
    with pytest.raises(ValueError, match="Amount exceeds maximum"):
        agent._validate_amount(Decimal("10000000000"))


def test_payment_execution(mock_gateway):
    """Test successful payment execution."""
    # Use fixtures for mocking
    agent = UAIP_Enterprise_SDK(
        agent_name="TestBot",
        company_name="TestCorp",
        secret_code=12345,
        gateway_url="http://mock-gateway",
        auto_register=False
    )
    
    result = agent.call_agent(
        task="Test payment",
        amount=Decimal("100.00"),
        intent="Test purpose",
        chain="BASE"
    )
    
    assert result['status'] == 'SUCCESS'
    assert 'settlement' in result
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_sdk.py

# Run specific test
pytest tests/test_sdk.py::test_agent_registration

# Run with coverage
pytest --cov=. --cov-report=html tests/

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"

# Run in verbose mode
pytest -v
```

### Test Coverage Requirements

- New code must have **≥80% test coverage**
- Critical security code must have **100% coverage**
- Run `pytest --cov` before submitting PR

---

## 🔄 Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass (`pytest`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No secrets or sensitive data committed
- [ ] Commit messages are clear and descriptive

### Commit Messages

Use conventional commits format:

```
type(scope): brief description

Longer description if needed.
Can span multiple lines.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(sdk): Add retry logic with exponential backoff

Added automatic retry for failed requests with configurable
max_retries and backoff multiplier.

Fixes #42
```

```
fix(gateway): Prevent SQL injection in agent lookup

Use parameterized queries instead of string formatting.

Security issue reported in #67
```

```
docs(quickstart): Add Docker deployment section

Added instructions for running UAIP with Docker Compose.
```

### Submitting Your PR

1. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create pull request on GitHub:**
   - Use the PR template
   - Link related issues
   - Describe changes clearly
   - Add screenshots if UI changes

3. **PR template:**
   ```markdown
   ## Description
   Brief description of changes.
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   Describe tests you added/ran.
   
   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Comments added for complex code
   - [ ] Documentation updated
   - [ ] Tests added/updated
   - [ ] All tests pass
   ```

### Review Process

1. **Automated checks run:**
   - CI/CD pipeline (GitHub Actions)
   - Code linting (flake8)
   - Tests (pytest)
   - Coverage check

2. **Maintainer review:**
   - Code quality
   - Test coverage
   - Documentation
   - Security implications

3. **Feedback and iteration:**
   - Address review comments
   - Push updates
   - Request re-review

4. **Merge:**
   - Maintainer merges when approved
   - Delete your branch after merge

---

## 🌟 Recognition

### Contributors

All contributors will be recognized in:
- `CONTRIBUTORS.md` file
- Release notes
- Project documentation

### Levels of Contribution

🥉 **Bronze** - 1-5 merged PRs
🥈 **Silver** - 6-15 merged PRs
🥇 **Gold** - 16+ merged PRs
💎 **Diamond** - Major feature or substantial improvement

---

## 💬 Community

### Get Help

- **Discord:** [discord.gg/uaip](https://discord.gg/uaip) (coming soon)
- **GitHub Discussions:** For questions and ideas
- **GitHub Issues:** For bugs and feature requests
- **Email:** uaip.protocol@gmail.com

### Communication Channels

- **GitHub:** Primary platform for code and issues
- **Discord:** Real-time chat and community
- **Twitter:** [@UAIP_Protocol](https://twitter.com/UAIP_Protocol) - Updates and announcements

### Office Hours

We host virtual office hours:
- **When:** Every Friday, 2 PM UTC
- **Where:** Discord voice channel
- **What:** Q&A, pair programming, discussions

---

## 📚 Additional Resources

- [QUICKSTART.md](QUICKSTART.md) - Get started in 5 minutes
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [api_docs.md](api_docs.md) - API reference
- [integrations_guide.md](integrations_guide.md) - Framework guides

---

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the same FSL-1.1-Apache-2.0 license as the project.

---

## 🙏 Thank You!

Your contributions make UAIP better for everyone. Whether you're fixing typos, adding features, or helping others in the community, thank you for being part of this project!

**Questions?** Open an issue or join our Discord. We're here to help!

---

<div align="center">

**Happy Contributing! 🎉**

[Back to Top](#-contributing-to-uaip)

</div>
