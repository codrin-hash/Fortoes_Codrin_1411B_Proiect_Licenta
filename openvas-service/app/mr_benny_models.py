"""
MrBenny API models for the OV1 service.

This module defines the request and response schemas used when
communicating with the MrBenny platform API (v1).

OV1 acts as an ingest agent: it sends vulnerability detection
observations to MrBenny via POST /api/v1/ingest/data, using
the Mode A authentication (static API key).

References:
    - student_documentation.md, sections 5.5, 7, 8
"""

from typing import Any, Optional
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Outbound — what OV1 sends to MrBenny
# ---------------------------------------------------------------------------

class MrBennyIdentifier(BaseModel):
    """
    A single identifier for a device observation.

    Accepted types (from documentation section 8):
        mac, ip, ipv6, hostname, fqdn, openvas_host_id, custom
    """
    type: str
    value: str


class MrBennyObservation(BaseModel):
    """
    One observation within an ingest event.

    Each observation describes one discovered host/device.
    The 'observation_ref' is a local reference used to correlate
    the id_map entries in the response back to this observation.

    Extra fields (vulnerabilities, scan metadata) are accepted by
    MrBenny and stored as-is, so we include them here as optional
    free-form data.
    """
    observation_ref: str
    identifiers: list[MrBennyIdentifier]
    vulnerabilities: Optional[list[dict[str, Any]]] = None
    scan_summary: Optional[dict[str, Any]] = None


class MrBennyIngestRequest(BaseModel):
    """
    Payload for POST /api/v1/ingest/data.

    Fields:
        client_event_id : unique per agent install, used for idempotency
        timestamp       : ISO-8601 logical time of the event
        event_type      : fixed to 'openvas_scan_result' for OV1
        observations    : list of host observations from the scan
    """
    client_event_id: str
    timestamp: str
    event_type: str = "openvas_scan_result"
    observations: list[MrBennyObservation]


# ---------------------------------------------------------------------------
# Inbound — what MrBenny returns after ingest
# ---------------------------------------------------------------------------

class MrBennyIdMapEntry(BaseModel):
    """
    One entry in the id_map_entries array from the ingest response.

    MrBenny resolves each identifier to a stable mrbenny_device_id.
    OV1 stores this mapping locally so it can reference devices
    in future interactions.
    """
    observation_ref: str
    identifier_type: str
    identifier_value: str
    mrbenny_device_id: str
    match_status: str
    match_confidence: Optional[float] = None


class MrBennyDeviceStatus(BaseModel):
    mrbenny_device_id: str
    trust_score: Optional[int] = None
    is_trusted: Optional[bool] = None
    probationary_until: Optional[str] = None


class MrBennyIngestResponseData(BaseModel):
    """
    The 'data' field inside a successful ingest response envelope.
    """
    server_event_id: str
    stored_at: str
    id_map: dict[str, str]
    id_map_entries: list[MrBennyIdMapEntry] = []
    device_status: list[MrBennyDeviceStatus] = []
    warnings: list[str] = []


class MrBennyIngestResponse(BaseModel):
    """
    Full envelope returned by MrBenny on a successful ingest call.
    """
    ok: bool
    idempotent_replay: bool = False
    data: Optional[MrBennyIngestResponseData] = None
    error_code: Optional[str] = None
    message: Optional[str] = None
    retryable: Optional[bool] = None