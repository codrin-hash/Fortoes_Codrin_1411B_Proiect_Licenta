"""
Transactional local journal for the OV1 service.

This module implements the local send journal required by the MrBenny
agent specification (student_documentation.md, section 12):

    "jurnal local pentru replay"

Every ingest event that OV1 attempts to send to MrBenny is first written
to the journal with status 'pending'. Once MrBenny confirms the event
(ok=true in the response), the entry is marked 'sent'. If the HTTP call
fails or MrBenny returns an error, the entry stays 'pending' and can be
retried later.

This guarantees at-least-once delivery: even if the service restarts
(in-memory journal resets), the current in-process queue is drained before
the background task exits. For production durability a persistent store
(SQLite, Redis) should replace the in-memory dict — this implementation
intentionally keeps the structure simple and swappable.

Journal entry lifecycle:
    pending  →  sent      (MrBenny accepted, ok=true, not idempotent_replay)
    pending  →  replayed  (MrBenny accepted, idempotent_replay=true)
    pending  →  failed    (non-retryable error from MrBenny)
    pending  →  pending   (retryable error — will be retried)

References:
    - student_documentation.md, sections 7, 12
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

logger = logging.getLogger(__name__)

JournalStatus = Literal["pending", "sent", "replayed", "failed"]


@dataclass
class JournalEntry:
    """
    One record in the local send journal.

    Attributes:
        journal_id      : internal UUID for this journal entry
        client_event_id : the MrBenny idempotency key sent in the payload
        scan_id         : OV1 internal scan identifier
        payload_json    : serialised MrBennyIngestRequest (JSON string)
        status          : current lifecycle status
        created_at      : when the entry was created (UTC)
        sent_at         : when MrBenny confirmed acceptance (UTC), or None
        server_event_id : the server-side ID returned by MrBenny, or None
        last_error      : last error message if delivery failed
        attempt_count   : how many send attempts have been made
    """
    journal_id: str
    client_event_id: str
    scan_id: str
    payload_json: str
    status: JournalStatus = "pending"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sent_at: Optional[str] = None
    server_event_id: Optional[str] = None
    last_error: Optional[str] = None
    attempt_count: int = 0


# In-memory store: journal_id -> JournalEntry
_JOURNAL: dict[str, JournalEntry] = {}


def add_entry(
    client_event_id: str,
    scan_id: str,
    payload_json: str,
) -> JournalEntry:
    """
    Create a new journal entry in 'pending' state.

    Call this BEFORE making the HTTP request to MrBenny so the event
    is recorded even if the process crashes mid-flight.
    """
    entry = JournalEntry(
        journal_id=str(uuid.uuid4()),
        client_event_id=client_event_id,
        scan_id=scan_id,
        payload_json=payload_json,
    )
    _JOURNAL[entry.journal_id] = entry
    logger.debug(
        "journal: added entry %s for scan %s (client_event_id=%s)",
        entry.journal_id,
        scan_id,
        client_event_id,
    )
    return entry


def mark_sent(
    journal_id: str,
    server_event_id: str,
    idempotent_replay: bool = False,
) -> None:
    """Mark a journal entry as successfully delivered."""
    entry = _JOURNAL.get(journal_id)
    if entry is None:
        logger.warning("journal: mark_sent called for unknown journal_id %s", journal_id)
        return

    entry.status = "replayed" if idempotent_replay else "sent"
    entry.sent_at = datetime.now(timezone.utc).isoformat()
    entry.server_event_id = server_event_id
    entry.attempt_count += 1

    logger.info(
        "journal: entry %s marked %s (server_event_id=%s)",
        journal_id,
        entry.status,
        server_event_id,
    )


def mark_failed(
    journal_id: str,
    error: str,
    retryable: bool = True,
) -> None:
    """
    Record a delivery failure.

    If retryable=True the entry stays 'pending' so the background task
    can retry it. If retryable=False the entry is marked 'failed' and
    will not be retried automatically.
    """
    entry = _JOURNAL.get(journal_id)
    if entry is None:
        logger.warning("journal: mark_failed called for unknown journal_id %s", journal_id)
        return

    entry.attempt_count += 1
    entry.last_error = error

    if not retryable:
        entry.status = "failed"
        logger.error(
            "journal: entry %s marked failed (non-retryable): %s",
            journal_id,
            error,
        )
    else:
        logger.warning(
            "journal: entry %s delivery attempt %d failed (retryable): %s",
            journal_id,
            entry.attempt_count,
            error,
        )


def get_pending_entries() -> list[JournalEntry]:
    """Return all entries still in 'pending' state, ordered by creation time."""
    pending = [e for e in _JOURNAL.values() if e.status == "pending"]
    pending.sort(key=lambda e: e.created_at)
    return pending


def get_entry(journal_id: str) -> Optional[JournalEntry]:
    return _JOURNAL.get(journal_id)


def get_all_entries() -> list[JournalEntry]:
    """Return all journal entries (for diagnostics / API exposure)."""
    return sorted(_JOURNAL.values(), key=lambda e: e.created_at)