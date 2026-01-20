"""
UAIP - Universal Agent Interoperability Protocol

The secure settlement layer for AI agents.
"""

__version__ = "1.0.0"

from .sdk import UAIP_Enterprise_SDK
from .gateway import app
from .compliance import ComplianceAuditor
from .settlement import FinancialSettlementEngine
from .privacy import ZKProofSystem

__all__ = [
    "UAIP_Enterprise_SDK",
    "app",
    "ComplianceAuditor", 
    "FinancialSettlementEngine",
    "ZKProofSystem"
]
