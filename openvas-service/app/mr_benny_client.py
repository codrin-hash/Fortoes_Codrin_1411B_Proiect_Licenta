"""
MrBenny API client for the OV1 service.

This module handles all HTTP communication between OV1 and the MrBenny
platform, using Mode A authentication (static API key via X-API-Key header).

Responsibilities:
    - Build and send POST /api/v1/ingest/data requests
    - Parse the MrBenny response envelope
    - Extract and return the id_map (identifier -> mrbenny_device_id)
    - Integrate with the local journal for at-least-once delivery

Mode A authentication headers (per student_documentation.md section 2.2):
    X-Mrbenny-Mode: A
    X-API-Key: <api_key>

References:
    - student_documentation.md, sections 2.2, 5.5, 6, 7
"""

import logging
from datetime import datetime, timezone

import httpx

from app import journal as Journal
from app import session_manager
from app.config import settings
from app.mr_benny_models import (
    MrBennyIngestRequest,
    MrBennyIngestResponse,
    MrBennyObservation,
    MrBennySourceContext,
)

logger = logging.getLogger(__name__)

# HTTP timeout for MrBenny requests (seconds)
_REQUEST_TIMEOUT = 15.0


def _build_headers() -> dict[str, str]:
    """
    Build authentication headers for MrBenny requests.

    Prefers Mode B1 (session token) when a session is active.
    Falls back to Mode A (static API key) when no session is open,
    which happens if MRBENNY_INSTALL_TOKEN is not configured or the
    session open failed at startup.
    """
    session_token = session_manager.get_session_token()

    if session_token:
        return {
            "X-Mrbenny-Mode": "B1",
            "Authorization": f"Bearer {session_token}",
            "Content-Type": "application/json",
        }

    # Mode A fallback
    return {
        "X-Mrbenny-Mode": "A",
        "X-API-Key": settings.mrbenny_api_key,
        "Content-Type": "application/json",
    }


def _build_client_event_id(scan_id: str) -> str:
    """
    Generate a unique, stable client_event_id for a given scan.

    Format: ov1-<scan_id>-<UTC-date>
    This is deterministic per scan per day, which makes retries
    within the same day idempotent (MrBenny deduplicates by this ID).
    """
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"ov1-{scan_id}-{date_str}"


def send_ingest(
    scan_id: str,
    observations: list[MrBennyObservation],
) -> dict[str, str]:
    """
    Send an ingest event to MrBenny and return the id_map.

    The id_map maps identifier strings (e.g. "ip:10.0.0.5") to
    stable mrbenny_device_id values (e.g. "dev_xxx"). OV1 stores
    this mapping so subsequent events can reference the same devices.

    The call is journaled:
        1. Entry created in 'pending' state BEFORE the HTTP call
        2. On success → entry marked 'sent' or 'replayed'
        3. On failure → entry stays 'pending' (retryable) or 'failed'

    Args:
        scan_id:      Internal OV1 scan identifier
        observations: List of MrBennyObservation built by result_mapper

    Returns:
        id_map dict (may be empty if MrBenny returned no mappings)

    Raises:
        RuntimeError: if MrBenny returns ok=false with a non-retryable
                      error. Retryable errors are logged but do NOT raise,
                      so the background task can retry later.
    """
    if not settings.mrbenny_base_url or not settings.mrbenny_api_key:
        logger.warning(
            "send_ingest: MrBenny base URL or API key not configured — skipping"
        )
        return {}

    client_event_id = _build_client_event_id(scan_id)
    timestamp = datetime.now(timezone.utc).isoformat()

    payload = MrBennyIngestRequest(
        client_event_id=client_event_id,
        timestamp=timestamp,
        source_context=MrBennySourceContext(scan_id=scan_id),
        observations=observations,
    )

    payload_json = payload.model_dump_json()

    # --- Step 1: write to journal BEFORE sending ---
    journal_entry = Journal.add_entry(
        client_event_id=client_event_id,
        scan_id=scan_id,
        payload_json=payload_json,
    )

    url = f"{settings.mrbenny_base_url.rstrip('/')}/api/v1/ingest/data"
    headers = _build_headers()

    logger.info(
        "send_ingest: sending scan=%s client_event_id=%s to %s",
        scan_id,
        client_event_id,
        url,
    )

    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            http_response = client.post(url, content=payload_json, headers=headers)

        raw = http_response.text
        logger.debug(
            "send_ingest: raw response status=%d body=%s",
            http_response.status_code,
            raw[:500],
        )

        if http_response.status_code in (401, 403):
            # Session token expired or revoked — attempt to renew and retry once
            logger.warning(
                "send_ingest: HTTP %d — session may have expired, attempting renewal",
                http_response.status_code,
            )
            session_manager.clear_session()
            renewed = session_manager.open_session()
            if renewed:
                headers = _build_headers()
                with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
                    http_response = client.post(url, content=payload_json, headers=headers)
                raw = http_response.text
            else:
                Journal.mark_failed(
                    journal_entry.journal_id,
                    error=f"HTTP {http_response.status_code}: session renewal failed",
                    retryable=True,
                )
                return {}

        if http_response.status_code == 409:
            Journal.mark_sent(
                journal_entry.journal_id,
                server_event_id="replay-conflict",
                idempotent_replay=True,
            )
            return {}

        if http_response.status_code == 429:
            logger.warning("send_ingest: rate limited (429) — will retry later")
            Journal.mark_failed(
                journal_entry.journal_id,
                error="429 rate limited",
                retryable=True,
            )
            return {}

        if http_response.status_code >= 500:
            Journal.mark_failed(
                journal_entry.journal_id,
                error=f"HTTP {http_response.status_code}: {raw[:200]}",
                retryable=True,
            )
            return {}

        # Parse envelope
        response_data = MrBennyIngestResponse.model_validate_json(raw)

        if not response_data.ok:
            retryable = response_data.retryable or False
            error_msg = f"{response_data.error_code}: {response_data.message}"
            Journal.mark_failed(
                journal_entry.journal_id,
                error=error_msg,
                retryable=retryable,
            )
            if not retryable:
                raise RuntimeError(f"MrBenny non-retryable error: {error_msg}")
            logger.warning("send_ingest: retryable error from MrBenny: %s", error_msg)
            return {}

        # --- Step 2: mark journal entry as sent ---
        server_event_id = (
            response_data.data.server_event_id if response_data.data else "unknown"
        )
        Journal.mark_sent(
            journal_entry.journal_id,
            server_event_id=server_event_id,
            idempotent_replay=response_data.idempotent_replay,
        )

        id_map = response_data.data.id_map if response_data.data else {}

        logger.info(
            "send_ingest: scan=%s accepted by MrBenny server_event_id=%s id_map=%s",
            scan_id,
            server_event_id,
            id_map,
        )

        return id_map

    except httpx.RequestError as exc:
        error_msg = f"HTTP request error: {exc}"
        logger.error("send_ingest: %s", error_msg)
        Journal.mark_failed(
            journal_entry.journal_id,
            error=error_msg,
            retryable=True,
        )
        return {}


def retry_pending_journal_entries() -> None:
    """
    Retry all journal entries still in 'pending' state.

    Called by the background polling task each cycle, after the main
    push logic. For each pending entry, re-sends the original payload
    to MrBenny using the same client_event_id — MrBenny's idempotency
    guarantees that duplicate deliveries are safe.

    Entries are retried using their stored payload_json so the content
    is identical to the original attempt. If MrBenny returns 409
    (idempotent replay), the entry is marked 'replayed' — not an error.
    """
    pending = Journal.get_pending_entries()
    if not pending:
        return

    logger.info("retry: %d pending journal entry/entries to retry", len(pending))

    url = f"{settings.mrbenny_base_url.rstrip('/')}/api/v1/ingest/data"
    headers = _build_headers()

    for entry in pending:
        logger.info(
            "retry: retrying journal_id=%s scan=%s attempt=%d",
            entry.journal_id,
            entry.scan_id,
            entry.attempt_count + 1,
        )

        try:
            with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
                http_response = client.post(
                    url, content=entry.payload_json, headers=headers
                )

            raw = http_response.text

            if http_response.status_code == 409:
                logger.info(
                    "retry: 409 for journal_id=%s — treating as replay",
                    entry.journal_id,
                )
                Journal.mark_sent(
                    entry.journal_id,
                    server_event_id="replay-conflict",
                    idempotent_replay=True,
                )
                continue

            if http_response.status_code == 429:
                logger.warning(
                    "retry: rate limited (429) for journal_id=%s — will retry later",
                    entry.journal_id,
                )
                Journal.mark_failed(
                    entry.journal_id, error="429 rate limited", retryable=True
                )
                continue

            if http_response.status_code >= 500:
                Journal.mark_failed(
                    entry.journal_id,
                    error=f"HTTP {http_response.status_code}: {raw[:200]}",
                    retryable=True,
                )
                continue

            response_data = MrBennyIngestResponse.model_validate_json(raw)

            if not response_data.ok:
                retryable = response_data.retryable or False
                error_msg = f"{response_data.error_code}: {response_data.message}"
                Journal.mark_failed(
                    entry.journal_id, error=error_msg, retryable=retryable
                )
                logger.warning(
                    "retry: journal_id=%s error from MrBenny (retryable=%s): %s",
                    entry.journal_id,
                    retryable,
                    error_msg,
                )
                continue

            server_event_id = (
                response_data.data.server_event_id if response_data.data else "unknown"
            )
            Journal.mark_sent(
                entry.journal_id,
                server_event_id=server_event_id,
                idempotent_replay=response_data.idempotent_replay,
            )
            logger.info(
                "retry: journal_id=%s delivered OK server_event_id=%s",
                entry.journal_id,
                server_event_id,
            )

        except httpx.RequestError as exc:
            logger.error(
                "retry: HTTP error for journal_id=%s: %s", entry.journal_id, exc
            )
            Journal.mark_failed(
                entry.journal_id,
                error=f"HTTP request error: {exc}",
                retryable=True,
            )