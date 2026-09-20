"""Error taxonomy for the Agent Immune System control plane.

Every refusal raised by the control plane is a subclass of ``ControlPlaneError``
so that callers can never accidentally treat a denial as a soft failure.
"""

from __future__ import annotations


class AISError(Exception):
    """Base class for every error raised by the prototype."""


class ControlPlaneError(AISError):
    """Raised when the control plane refuses an operation."""

    code = "CONTROL_PLANE_ERROR"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.context = context

    def as_dict(self) -> dict:
        return {"code": self.code, "message": str(self), "context": self.context}


class IdentityError(ControlPlaneError):
    code = "IDENTITY_ERROR"


class AuthenticationFailed(IdentityError):
    code = "AUTHENTICATION_FAILED"


class ImpersonationDetected(IdentityError):
    code = "IMPERSONATION_DETECTED"


class AuthorityError(ControlPlaneError):
    code = "AUTHORITY_ERROR"


class SelfGrantDenied(AuthorityError):
    """Principle 2 - authority is external. No principal may grant itself authority."""

    code = "SELF_GRANT_DENIED"


class AuthorityAmplification(AuthorityError):
    """Principle 3 - delegation may only attenuate authority."""

    code = "AUTHORITY_AMPLIFICATION"


class AuthorityRevoked(AuthorityError):
    code = "AUTHORITY_REVOKED"


class AuthorityExpired(AuthorityError):
    code = "AUTHORITY_EXPIRED"


class ForbiddenCapability(AuthorityError):
    """Capabilities that this architecture refuses to model at all (offensive actions)."""

    code = "FORBIDDEN_CAPABILITY"


class ContractError(ControlPlaneError):
    code = "CONTRACT_ERROR"


class ContractIntegrityError(ContractError):
    code = "CONTRACT_INTEGRITY_ERROR"


class PolicyError(ControlPlaneError):
    code = "POLICY_ERROR"


class PolicyIntegrityError(PolicyError):
    code = "POLICY_INTEGRITY_ERROR"


class DelegationError(ControlPlaneError):
    code = "DELEGATION_ERROR"


class ContainmentError(ControlPlaneError):
    code = "CONTAINMENT_ERROR"


class QuarantineEscape(ContainmentError):
    code = "QUARANTINE_ESCAPE"


class EmergencyControlError(ControlPlaneError):
    """Emergency controls are operated out-of-band; agents cannot reach them."""

    code = "EMERGENCY_CONTROL_ERROR"


class AuditIntegrityError(ControlPlaneError):
    code = "AUDIT_INTEGRITY_ERROR"
