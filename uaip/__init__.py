"""
UAIP Protocol - Secure settlement layer for AI agents.

Simple usage:
    >>> from uaip import UAIPAgent
    >>> agent = UAIPAgent(name="MyBot", company="MyCo")
    >>> receipt = agent.pay(to_agent="did:uaip:xyz", amount=50.00)
"""

from .client import UAIPAgent
from .exceptions import UAIPError, ComplianceError, SettlementError

__version__ = "0.1.0"
__all__ = ["UAIPAgent", "UAIPError", "ComplianceError", "SettlementError"]