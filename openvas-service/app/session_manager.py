"""
MrBenny B1 session manager for the OV1 service.

Handles the session lifecycle required by Mode B1 authentication:
    1. At startup, exchanges the install token for a session token via
       POST /api/v1/auth/session
    2. Stores the session token in memory for use by mr_benny_client
    3. Exposes helpers to retrieve the active token and check validity

The session token has a finite lifetime (session_expires_at from the
server response). If the token is close to expiry or a request fails
with 401/403, the client should call open_session() again to renew it.

If MRBENNY_INSTALL_TOKEN is not configured, the manager stays inactive
and mr_benny_client falls back to Mode A.

References:
    - student_documentation.md, sections 2.3, 5.4
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 15.0


@dataclass
class SessionState:
    agent_install_id: str
    session_token: str
    session_expires_at: str
    opened_at: str


# Module-level session state — None until open_session() succeeds
_session: Optional[SessionState] = None


def open_session() -> bool:
    """
    Exchange the install token for a B1 session token.

    Sends POST /api/v1/auth/session with the configured install token
    and stores the returned session_token for use in subsequent requests.

    Returns True on success, False if the call fails or the install
    token is not configured. On failure the service continues running
    in Mode A (if MRBENNY_API_KEY is set).
    """
    global _session

    if not settings.mrbenny_install_token:
        logger.info("session_manager: MRBENNY_INSTALL_TOKEN not set — skipping B1 session")
        return False

    if not settings.mrbenny_base_url:
        logger.warning("session_manager: MRBENNY_BASE_URL not set — cannot open session")
        return False

    url = f"{settings.mrbenny_base_url.rstrip('/')}/api/v1/auth/session"

    payload = {
        "agent_type": "OV1",
        "hardware_uuid": settings.mrbenny_hardware_uuid,
        "install_token": settings.mrbenny_install_token,
        "agent_version": settings.mrbenny_agent_version,
        "host_label": settings.mrbenny_host_label,
    }

    headers = {
        "X-Mrbenny-Mode": "B1",
        "Content-Type": "application/json",
    }

    logger.info("session_manager: opening B1 session at %s", url)

    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            response = client.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            logger.error(
                "session_manager: session open failed HTTP %d: %s",
                response.status_code,
                response.text[:300],
            )
            return False

        data = response.json()

        if not data.get("ok"):
            logger.error(
                "session_manager: server returned ok=false: %s",
                data.get("message"),
            )
            return False

        session_data = data["data"]
        _session = SessionState(
            agent_install_id=session_data["agent_install_id"],
            session_token=session_data["session_token"],
            session_expires_at=session_data["session_expires_at"],
            opened_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(
            "session_manager: B1 session opened — agent_install_id=%s expires_at=%s",
            _session.agent_install_id,
            _session.session_expires_at,
        )
        return True

    except httpx.RequestError as exc:
        logger.error("session_manager: HTTP error opening session: %s", exc)
        return False


def get_session_token() -> Optional[str]:
    """Return the active session token, or None if no session is open."""
    return _session.session_token if _session else None


def get_agent_install_id() -> Optional[str]:
    """Return the agent_install_id assigned by MrBenny, or None."""
    return _session.agent_install_id if _session else None


def is_active() -> bool:
    """Return True if a B1 session is currently open."""
    return _session is not None


def clear_session() -> None:
    """Invalidate the current session (e.g. after a 401/403 response)."""
    global _session
    _session = None
    logger.info("session_manager: session cleared")