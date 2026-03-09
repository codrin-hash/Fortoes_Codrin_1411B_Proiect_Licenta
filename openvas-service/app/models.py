"""
Data models for the OV1 service.

This module defines the request and response schemas used by the API.
The models describe how scan jobs are created, how scan status is returned,
and how scan results are represented inside the service.
"""

from typing import Optional, Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    asset_id: str = Field(..., description="Unique asset identifier received from MrBenny")
    ip_address: str = Field(..., description="IP address of the asset up for the scan")
    hostname: str = Field(..., description="Asset hostname")


class ScanCreateResponse(BaseModel):
    scan_id: str
    task_id: str
    target_id: str
    status: Literal["created"]


class ScanStatusResponse(BaseModel):
    scan_id: str
    task_id: str
    status: str
    progress: Optional[int] = None


class ScanResultResponse(BaseModel):
    scan_id: str
    report_id: str
    status: Literal["ready"]
    content: dict