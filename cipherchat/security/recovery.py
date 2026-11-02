"""Explicit bounded recovery state machine; it never retries automatically."""
from enum import Enum


class RecoveryState(str, Enum):
    SECURE = "SECURE"
    SUSPECTED_ATTACK = "SUSPECTED_ATTACK"
    QUARANTINED = "QUARANTINED"
    VERIFYING = "VERIFYING"
    REKEYING = "REKEYING"
    BLOCKED = "BLOCKED"


class InvalidTransition(Exception):
    pass


_ALLOWED = {
    RecoveryState.SECURE: {RecoveryState.SUSPECTED_ATTACK},
    RecoveryState.SUSPECTED_ATTACK: {RecoveryState.QUARANTINED},
    RecoveryState.QUARANTINED: {RecoveryState.VERIFYING},
    RecoveryState.VERIFYING: {RecoveryState.REKEYING, RecoveryState.BLOCKED},
    RecoveryState.REKEYING: {RecoveryState.SECURE},
    RecoveryState.BLOCKED: set(),
}


class RecoveryMachine:
    def __init__(self) -> None:
        self.state = RecoveryState.SECURE
        self.history = [self.state]

    def transition(self, target: RecoveryState) -> None:
        if target not in _ALLOWED[self.state]:
            raise InvalidTransition(f"{self.state} -> {target} is not allowed")
        self.state = target
        self.history.append(target)

    def report_violation(self) -> None:
        self.transition(RecoveryState.SUSPECTED_ATTACK)
        self.transition(RecoveryState.QUARANTINED)

    def begin_verification(self) -> None:
        self.transition(RecoveryState.VERIFYING)

    def verification_succeeded(self) -> None:
        self.transition(RecoveryState.REKEYING)

    def rekey_complete(self) -> None:
        self.transition(RecoveryState.SECURE)

    def verification_failed(self) -> None:
        self.transition(RecoveryState.BLOCKED)
