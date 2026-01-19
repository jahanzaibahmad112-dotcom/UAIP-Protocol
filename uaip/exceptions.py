"""Custom exceptions for UAIP."""


class UAIPError(Exception):
    """Base exception for UAIP errors."""
    pass


class ComplianceError(UAIPError):
    """Raised when action violates compliance rules."""
    pass


class SettlementError(UAIPError):
    """Raised when blockchain settlement fails."""
    pass


class AuthorizationError(UAIPError):
    """Raised when authorization is denied."""
    pass