"""Tamper evident audit log.

Every consequential decision is appended to a hash chain:

    hash_n = SHA256( canonical(record_n) || hash_{n-1} )

Any mutation, deletion or reordering of earlier entries breaks verification at
the first altered index. The log is append only through its public API; the
adversarial suite mutates the backing list directly to prove detection works
(``tests/adversarial/test_audit_tampering.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..common.errors import AuditIntegrityError
from ..common.util import IdFactory, LogicalClock, canonical_json, encodable, sha256_hex

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    record_id: str
    sequence: int
    timestamp: int
    event_type: str
    actor_id: str | None
    subject_id: str | None
    task_id: str | None
    payload: dict = field(default_factory=dict)
    prev_hash: str = GENESIS
    record_hash: str = ""

    def body(self) -> dict:
        return {
            "record_id": self.record_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "task_id": self.task_id,
            "payload": encodable(self.payload),
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.body()) + self.prev_hash)


@dataclass(frozen=True)
class IntegrityReport:
    valid: bool
    length: int
    broken_at: int | None = None
    reason: str | None = None


class AuditService:
    """Append only, searchable, correlatable, replayable event ledger."""

    def __init__(self, clock: LogicalClock, ids: IdFactory) -> None:
        self._clock = clock
        self._ids = ids
        self._records: list[AuditRecord] = []
        self._subscribers: list[Callable[[AuditRecord], None]] = []

    # -- writing -----------------------------------------------------------
    def append(
        self,
        event_type: str,
        *,
        actor_id: str | None = None,
        subject_id: str | None = None,
        task_id: str | None = None,
        payload: dict | None = None,
    ) -> AuditRecord:
        prev = self._records[-1].record_hash if self._records else GENESIS
        record = AuditRecord(
            record_id=self._ids.new("AUD"),
            sequence=len(self._records),
            timestamp=self._clock.now,
            event_type=event_type,
            actor_id=actor_id,
            subject_id=subject_id,
            task_id=task_id,
            payload=dict(payload or {}),
            prev_hash=prev,
        )
        record = AuditRecord(**{**record.__dict__, "record_hash": record.compute_hash()})
        self._records.append(record)
        for subscriber in self._subscribers:
            subscriber(record)
        return record

    def subscribe(self, callback: Callable[[AuditRecord], None]) -> None:
        self._subscribers.append(callback)

    # -- reading -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._records)

    def all(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def head_hash(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS

    def search(
        self,
        *,
        event_type: str | None = None,
        actor_id: str | None = None,
        subject_id: str | None = None,
        task_id: str | None = None,
        since: int | None = None,
        predicate: Callable[[AuditRecord], bool] | None = None,
    ) -> list[AuditRecord]:
        results = []
        for record in self._records:
            if event_type and record.event_type != event_type:
                continue
            if actor_id and record.actor_id != actor_id:
                continue
            if subject_id and record.subject_id != subject_id:
                continue
            if task_id and record.task_id != task_id:
                continue
            if since is not None and record.timestamp < since:
                continue
            if predicate and not predicate(record):
                continue
            results.append(record)
        return results

    def correlate(self, task_id: str) -> list[AuditRecord]:
        """All records belonging to one task, in causal (append) order."""
        return self.search(task_id=task_id)

    def replay(self, filter_fn: Callable[[AuditRecord], bool] | None = None) -> Iterable[dict]:
        """Yield decision bodies for deterministic replay by forensics."""
        for record in self._records:
            if filter_fn is None or filter_fn(record):
                yield record.body()

    # -- integrity ---------------------------------------------------------
    def verify(self) -> IntegrityReport:
        prev = GENESIS
        for index, record in enumerate(self._records):
            if record.sequence != index:
                return IntegrityReport(False, len(self._records), index, "sequence mismatch")
            if record.prev_hash != prev:
                return IntegrityReport(False, len(self._records), index, "chain link mismatch")
            if record.compute_hash() != record.record_hash:
                return IntegrityReport(False, len(self._records), index, "record hash mismatch")
            prev = record.record_hash
        return IntegrityReport(True, len(self._records))

    def assert_intact(self) -> None:
        report = self.verify()
        if not report.valid:
            raise AuditIntegrityError(
                "audit chain verification failed",
                broken_at=report.broken_at,
                reason=report.reason,
            )

    # -- export ------------------------------------------------------------
    def to_jsonl(self) -> str:
        return "\n".join(
            canonical_json({**record.body(), "prev_hash": record.prev_hash, "hash": record.record_hash})
            for record in self._records
        )

    def snapshot(self) -> dict[str, Any]:
        return {"length": len(self._records), "head": self.head_hash()}
