"""
In-memory storage for OV1 scan jobs.

This module keeps the internal state of scan requests handled by the OV1 service.
It stores the association between the internal scan identifier and the OpenVAS
identifiers created during the scanning workflow.

Extended fields compared to the initial version:
    report_id          : OpenVAS report ID (populated when scan finishes)
    mrbenny_pushed     : True once the scan result has been successfully sent
                         to MrBenny via POST /api/v1/ingest/data
    mrbenny_device_ids : the id_map returned by MrBenny after ingest
                         (maps "ip:x.x.x.x" / "mac:AA:BB:..." to "dev_xxx")
"""

from dataclasses import dataclass, field
from typing import Optional
import uuid


@dataclass
class ScanRecord:
    scan_id: str
    asset_id: str
    hostname: str
    ip_address: str
    target_id: str
    task_id: str
    report_id: Optional[str] = None
    status: str = "created"
    progress: Optional[int] = None
    # MrBenny push state
    mrbenny_pushed: bool = False
    mrbenny_device_ids: dict[str, str] = field(default_factory=dict)


SCAN_STORE: dict[str, ScanRecord] = {}


def create_scan_record(
    asset_id: str,
    hostname: str,
    ip_address: str,
    target_id: str,
    task_id: str,
) -> ScanRecord:
    scan_id = str(uuid.uuid4())

    record = ScanRecord(
        scan_id=scan_id,
        asset_id=asset_id,
        hostname=hostname,
        ip_address=ip_address,
        target_id=target_id,
        task_id=task_id,
    )

    SCAN_STORE[scan_id] = record
    return record


def get_scan_record(scan_id: str) -> Optional[ScanRecord]:
    return SCAN_STORE.get(scan_id)


def update_scan_status(
    scan_id: str,
    status: str,
    progress: Optional[int] = None,
    report_id: Optional[str] = None,
) -> Optional[ScanRecord]:
    record = SCAN_STORE.get(scan_id)

    if record is None:
        return None

    record.status = status
    record.progress = progress

    if report_id is not None:
        record.report_id = report_id

    return record


def mark_mrbenny_pushed(
    scan_id: str,
    id_map: dict[str, str],
) -> Optional[ScanRecord]:
    """
    Mark a scan as successfully pushed to MrBenny and store the id_map.

    The id_map maps identifier strings to stable mrbenny_device_id values,
    e.g. {"ip:10.0.0.5": "dev_xxx", "mac:AA:BB:CC:DD:EE:FF": "dev_xxx"}.

    This mapping is stored locally so OV1 can reference the same devices
    in future events without relying on MrBenny resolving them again.
    """
    record = SCAN_STORE.get(scan_id)

    if record is None:
        return None

    record.mrbenny_pushed = True
    record.mrbenny_device_ids = id_map

    return record


def get_scans_pending_push() -> list[ScanRecord]:
    """
    Return all scans that are finished (status == 'Done') but have
    not yet been pushed to MrBenny.

    Used by the background polling task to decide which scans need
    to be processed and sent.
    """
    return [
        r for r in SCAN_STORE.values()
        if r.status == "Done" and not r.mrbenny_pushed
    ]