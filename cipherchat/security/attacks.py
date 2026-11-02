from enum import Enum
from cipherchat.crypto.encryption import AuthenticationError
from cipherchat.protocol.messages import DigitalSignatureError, ReplayError, ValidationError


class AttackType(str, Enum):
    REPLAY = "REPLAY"
    TAMPERING = "TAMPERING"
    INVALID_AUTHENTICATION = "INVALID_AUTHENTICATION"
    KEY_SUBSTITUTION = "KEY_SUBSTITUTION"
    UNKNOWN = "UNKNOWN"


class KeySubstitutionError(Exception):
    """Raised when the presented key does not match the pinned expectation."""
    pass


def classify_failure(error: Exception) -> AttackType:
    if isinstance(error, ReplayError):
        return AttackType.REPLAY
    if isinstance(error, DigitalSignatureError):
        return AttackType.TAMPERING
    if isinstance(error, AuthenticationError):
        return AttackType.TAMPERING
    if isinstance(error, ValidationError):
        return AttackType.INVALID_AUTHENTICATION
    if isinstance(error, KeySubstitutionError):
        return AttackType.KEY_SUBSTITUTION
    return AttackType.UNKNOWN


def verify_expected_public_key(expected: bytes, presented: bytes) -> None:
    """Detect pin mismatch; this is evidence of substitution, not MITM proof."""
    if expected != presented:
        raise KeySubstitutionError("presented public key differs from expected identity binding")
