"""
In-memory storage for OV1 scan jobs.

This module keeps the internal state of scan requests handled by the OV1 service.
It stores the association between the internal scan identifier and the OpenVAS
identifiers created during the scanning workflow.
"""

from dataclasses import dataclass
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