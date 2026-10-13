"""Privacy-preserving, tamper-evident incident record hash chain."""
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from cipherchat.protocol.limits import MAX_ID_LENGTH
from .attacks import AttackType

GENESIS_HASH = "0" * 64

@dataclass(frozen=True)
class IncidentEvidence:
    incident_id: str
    timestamp: str
    session_id: str
    attack_type: str
    message_id: str | None
    sequence_number: int | None
    description: str
    previous_evidence_hash: str
    evidence_hash: str

    def material(self) -> dict[str, object]:
        data = asdict(self); data.pop("evidence_hash")
        return data

@dataclass(frozen=True)
class EvidenceCheckpoint:
    """A chain tip and length retained independently from the evidence store."""
    record_count: int
    evidence_hash: str

def _hash(record: IncidentEvidence) -> str:
    return hashlib.sha256(json.dumps(record.material(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

class EvidenceLog:
    def __init__(self) -> None: self.records: list[IncidentEvidence] = []

    def record(self, *, session_id: str, attack_type: AttackType, description: str, message_id: str | None = None, sequence_number: int | None = None, timestamp: str | None = None) -> IncidentEvidence:
        if not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_LENGTH:
            raise ValueError(f"session_id must be non-empty string <= {MAX_ID_LENGTH} characters")
        if message_id is not None and (not isinstance(message_id, str) or len(message_id) > MAX_ID_LENGTH):
            raise ValueError(f"message_id must be string <= {MAX_ID_LENGTH} characters")
        previous = self.records[-1].evidence_hash if self.records else GENESIS_HASH
        draft = IncidentEvidence(str(uuid4()), timestamp or datetime.now(timezone.utc).isoformat(), session_id, attack_type.value, message_id, sequence_number, description, previous, "")
        item = replace(draft, evidence_hash=_hash(draft))
        self.records.append(item)
        return item

    def checkpoint(self) -> EvidenceCheckpoint:
        """Export this value to trusted/independent storage to detect truncation."""
        tip = self.records[-1].evidence_hash if self.records else GENESIS_HASH
        return EvidenceCheckpoint(record_count=len(self.records), evidence_hash=tip)

    def to_dict(self) -> dict[str, object]:
        """Convert evidence log to structured dictionary with complete integrity metadata."""
        cp = self.checkpoint()
        return {
            "format": "cipherchat-evidence-log-v1",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(self.records),
            "tip_evidence_hash": cp.evidence_hash,
            "chain_valid": verify_evidence_chain(self.records, cp),
            "checkpoint": asdict(cp),
            "records": [asdict(record) for record in self.records],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize evidence log with all relevant incident metadata to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def export_json(self, path: Path | str, indent: int = 2) -> Path:
        """Store evidence log to a JSON file including all relevant audit information."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self.to_json(indent=indent), encoding="utf-8")
        return out_path

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "EvidenceLog":
        log = cls()
        for item in data.get("records", []):
            log.records.append(IncidentEvidence(**item))
        return log

    @classmethod
    def from_json(cls, raw: str) -> "EvidenceLog":
        return cls.from_dict(json.loads(raw))

def verify_evidence_chain(records: list[IncidentEvidence], checkpoint: EvidenceCheckpoint | None = None) -> bool:
    previous = GENESIS_HASH
    for record in records:
        if record.previous_evidence_hash != previous or record.evidence_hash != _hash(record): return False
        previous = record.evidence_hash
    if checkpoint is not None and (len(records) != checkpoint.record_count or previous != checkpoint.evidence_hash):
        return False
    return True
