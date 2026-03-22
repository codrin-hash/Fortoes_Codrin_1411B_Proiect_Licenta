"""
Main API entrypoint for the OV1 service.

This module exposes the REST API used to interact with the OV1 OpenVAS
integration service. It allows external systems (such as MrBenny) to:

- create new vulnerability scans
- check scan status
- retrieve scan results

The module orchestrates the interaction between the API layer, the
OpenVAS client, and the internal scan storage.
"""
import traceback

from fastapi import FastAPI, Depends, HTTPException

from app.config import settings
from app.security import require_token
from app.models import (
    ScanRequest,
    ScanCreateResponse,
    ScanStatusResponse,
)
from app.storage import (
    create_scan_record,
    get_scan_record,
    update_scan_status,
)
from app.openvas_client import OpenVASClient


app = FastAPI(title="OV1 OpenVAS Integration Service")

openvas = OpenVASClient()

# default OpenVAS scan profile (Full and Fast)
DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"


@app.on_event("startup")
def startup_event():
    settings.validate()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post(
    "/scans",
    response_model=ScanCreateResponse,
    dependencies=[Depends(require_token)],
)
def create_scan(request: ScanRequest):
    try:
        target_name = f"{request.hostname}-{request.ip_address}"

        target_id = openvas.create_target(
            name=target_name,
            host=request.ip_address,
        )

        task_name = f"scan-{request.hostname}"

        task_id = openvas.create_task(
            name=task_name,
            target_id=target_id,
            scan_config_id=DEFAULT_SCAN_CONFIG_ID,
        )

        openvas.start_task(task_id)

        record = create_scan_record(
            asset_id=request.asset_id,
            hostname=request.hostname,
            ip_address=request.ip_address,
            target_id=target_id,
            task_id=task_id,
        )

        return ScanCreateResponse(
            scan_id=record.scan_id,
            task_id=record.task_id,
            target_id=record.target_id,
            status="created",
        )

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/scans/{scan_id}",
    response_model=ScanStatusResponse,
    dependencies=[Depends(require_token)],
)
def get_scan_status(scan_id: str):
    record = get_scan_record(scan_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    status_info = openvas.get_task_status(record.task_id)

    update_scan_status(
        scan_id=scan_id,
        status=status_info["status"],
        progress=status_info["progress"],
    )

    return ScanStatusResponse(
        scan_id=record.scan_id,
        task_id=record.task_id,
        status=status_info["status"],
        progress=status_info["progress"],
    )