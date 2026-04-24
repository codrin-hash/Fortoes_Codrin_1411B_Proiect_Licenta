"""
MrBenny API models for the OV1 service.

This module defines the request and response schemas used when
communicating with the MrBenny platform API (v1).

OV1 acts as an ingest agent: it sends vulnerability detection
observations to MrBenny via POST /api/v1/ingest/data, using
the Mode A authentication (static API key).

References:
    - student_documentation.md, sections 5.5, 7, 8
    - ov1_ingest_vulnerability_detection.json
"""

from typing import Any, Optional
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Outbound — what OV1 sends to MrBenny
# ---------------------------------------------------------------------------

class MrBennyIdentifier(BaseModel):
    """
    # A single identifier for a device observation.
    """
    type: str
    value: str


class MrBennyFinding(BaseModel):
    """
    A single vulnerability finding attached to an observation.

    Follows the structure from ov1_ingest_vulnerability_detection.json:
        finding_type : always "vulnerability" for OV1
        code         : CVE ID if available, otherwise NVT OID
        severity     : severity class string — "critical", "high", "medium", "low", "log"
        title        : human-readable vulnerability name
        description  : detailed description from OpenVAS (optional)
        port         : port/protocol where the finding was detected (optional)
        nvt_oid      : OpenVAS NVT OID for cross-reference (optional)
    """
    finding_type: str = "vulnerability"
    code: str
    severity: str
    title: str
    description: Optional[str] = None
    port: Optional[str] = None
    nvt_oid: Optional[str] = None


class MrBennyObservation(BaseModel):
    """
    One observation within an ingest event.

    Each observation describes one scanned host/device.

    Fields:
        observation_ref  : local reference to correlate id_map entries
                           in the MrBenny response back to this host
        agent_local_ref  : internal OpenVAS host reference
                           (e.g. "openvas-host-<openvas_host_id>")
        identifiers      : list of identifiers (ip, mac, hostname, etc.)
        attributes       : free-form host metadata (e.g. {"os": "Windows 11"})
        findings         : list of vulnerability findings for this host
    """
    observation_ref: str
    agent_local_ref: Optional[str] = None
    identifiers: list[MrBennyIdentifier]
    attributes: Optional[dict[str, Any]] = None
    findings: Optional[list[MrBennyFinding]] = None


class MrBennySourceContext(BaseModel):
    """
    Metadata about the OpenVAS scan that produced this event.

    Follows the structure from ov1_ingest_vulnerability_detection.json:
        scan_id : internal OV1 scan identifier
        scanner : scanner name, always "openvas-main" for OV1
    """
    scan_id: str
    scanner: str = "openvas-main"


class MrBennyIngestRequest(BaseModel):
    """
    Payload for POST /api/v1/ingest/data.

    Fields:
        client_event_id : unique per agent install, used for idempotency
        timestamp       : ISO-8601 logical time of the event
        event_type      : "vulnerability_detection" for OV1
        source_context  : metadata about the originating OpenVAS scan
        observations    : list of host observations from the scan
    """
    client_event_id: str
    timestamp: str
    event_type: str = "vulnerability_detection"
    source_context: Optional[MrBennySourceContext] = None
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