"""
Main API entrypoint for the OV1 service.

This module exposes the REST API used to interact with the OV1 OpenVAS
integration service. It allows external systems (such as MrBenny) to:

- create new vulnerability scans
- check scan status
- retrieve scan results

The module also runs a background polling task that:
    1. Periodically checks all active scans for completion
    2. Downloads the OpenVAS report for completed scans
    3. Maps the report to MrBenny observations via result_mapper
    4. Pushes the observations to MrBenny via mr_benny_client
    5. Stores the returned id_map (mrbenny_device_id) locally

This implements the OV1 specification:
    - runs independently
    - sends MAC + IP + detections to MrBenny
    - receives unique device IDs (mrbenny_device_id) and stores them
    - has a local transactional send journal
"""

import asyncio
import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException

from app.config import settings
from app.security import require_token
from app.models.models import (
    ScanRequest,
    ScanCreateResponse,
    ScanStatusResponse,
)
from app.core.storage import (
    create_scan_record,
    get_scan_record,
    get_scans_pending_push,
    mark_mrbenny_pushed,
    update_scan_status,
    SCAN_STORE,
)
from app.clients.openvas_client import OpenVASClient
from app.clients import mr_benny_client
from app.clients import google_drive_client
from app.core import result_mapper
from app import session_manager

logger = logging.getLogger(__name__)

openvas = OpenVASClient()

# default OpenVAS scan profile (Full and Fast)
DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"

# OpenVAS terminal statuses — once a task reaches these, it will not change
TERMINAL_STATUSES = {"Done", "Stopped", "Interrupted"}


# ---------------------------------------------------------------------------
# Background polling task
# ---------------------------------------------------------------------------

async def _poll_and_push_loop():
    """
    Background coroutine that polls OpenVAS for completed scans and
    pushes results to MrBenny.

    Runs indefinitely at POLL_INTERVAL_SECONDS intervals. Each cycle:
        1. Finds scans in 'Done' status not yet pushed (get_scans_pending_push)
        2. Fetches the report from OpenVAS
        3. Maps the XML report to MrBenny observations
        4. Calls mr_benny_client.send_ingest — this journals + sends
        5. Stores the id_map returned by MrBenny
        6. Also updates any still-running scans with their current status
    """
    logger.info(
        "Background poll-and-push task started (interval=%ds)",
        settings.poll_interval_seconds,
    )

    while True:
        try:
            await _poll_cycle()
        except Exception:
            logger.error(
                "Unhandled error in poll cycle:\n%s", traceback.format_exc()
            )

        await asyncio.sleep(settings.poll_interval_seconds)


async def _poll_cycle():
    """Execute one full polling cycle (runs in the asyncio event loop)."""

    # --- Step A: update status for all non-terminal scans ---
    active_scans = [
        r for r in SCAN_STORE.values()
        if r.status not in TERMINAL_STATUSES and not r.mrbenny_pushed
    ]

    for record in active_scans:
        try:
            status_info = await asyncio.to_thread(
                openvas.get_task_status, record.task_id
            )
            new_status = status_info.get("status") or record.status
            new_progress = status_info.get("progress")

            if new_status != record.status:
                logger.info(
                    "poll: scan %s status %s -> %s (progress=%s)",
                    record.scan_id, record.status, new_status, new_progress,
                )

            # If the scan just finished, grab the report_id
            if new_status in TERMINAL_STATUSES and record.report_id is None:
                report_id = await asyncio.to_thread(
                    openvas.get_report_id_from_task, record.task_id
                )
                update_scan_status(
                    scan_id=record.scan_id,
                    status=new_status,
                    progress=new_progress,
                    report_id=report_id,
                )
            else:
                update_scan_status(
                    scan_id=record.scan_id,
                    status=new_status,
                    progress=new_progress,
                )

        except Exception:
            logger.warning(
                "poll: failed to update status for scan %s:\n%s",
                record.scan_id,
                traceback.format_exc(),
            )

    # --- Step B: push completed scans to MrBenny ---
    for record in get_scans_pending_push():
        if record.report_id is None:
            try:
                report_id = await asyncio.to_thread(
                    openvas.get_report_id_from_task, record.task_id
                )
                if report_id:
                    update_scan_status(
                        scan_id=record.scan_id,
                        status=record.status,
                        progress=record.progress,
                        report_id=report_id,
                    )
                    record.report_id = report_id
            except Exception:
                logger.warning(
                    "poll: could not get report_id for scan %s", record.scan_id
                )
                continue

        if record.report_id is None:
            logger.info("poll: scan %s has no report yet, skipping", record.scan_id)
            continue

        try:
            logger.info(
                "poll: downloading report %s for scan %s",
                record.report_id, record.scan_id,
            )
            report_xml = await asyncio.to_thread(
                openvas.get_report, record.report_id
            )

            observations = result_mapper.map_report_to_observations(
                report_xml=report_xml,
                scan_id=record.scan_id,
            )

            if not observations:
                logger.warning(
                    "poll: scan %s produced no observations — marking pushed anyway",
                    record.scan_id,
                )
                mark_mrbenny_pushed(record.scan_id, id_map={})
                continue

            logger.info(
                "poll: pushing %d observation(s) for scan %s to MrBenny",
                len(observations), record.scan_id,
            )

            id_map = await asyncio.to_thread(
                mr_benny_client.send_ingest,
                record.scan_id,
                observations,
            )

            mark_mrbenny_pushed(record.scan_id, id_map=id_map)

            logger.info(
                "poll: scan %s pushed to MrBenny; device_ids=%s",
                record.scan_id, id_map,
            )

        except Exception:
            logger.error(
                "poll: failed to push scan %s to MrBenny:\n%s",
                record.scan_id,
                traceback.format_exc(),
            )
            # Do NOT mark as pushed — will retry next cycle

    # --- Step C: retry pending journal entries ---
    await asyncio.to_thread(mr_benny_client.retry_pending_journal_entries)


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate()
    await asyncio.to_thread(session_manager.open_session)
    task = asyncio.create_task(_poll_and_push_loop())
    logger.info("OV1 service started; background poll task created")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("OV1 service shutting down")


app = FastAPI(title="OV1 OpenVAS Integration Service", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

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


@app.get(
    "/scans/{scan_id}/results",
    dependencies=[Depends(require_token)],
)
def get_scan_results(scan_id: str):
    """
    Return the current MrBenny push state for a finished scan.

    Includes:
        - Whether the scan has been pushed to MrBenny
        - The mrbenny_device_ids (id_map) received from MrBenny
        - The report_id from OpenVAS
    """
    record = get_scan_record(scan_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": record.scan_id,
        "status": record.status,
        "report_id": record.report_id,
        "mrbenny_pushed": record.mrbenny_pushed,
        "mrbenny_device_ids": record.mrbenny_device_ids,
    }


@app.post("/scans/{scan_id}/upload_drive", dependencies=[Depends(require_token)])
def upload_scan_to_drive(scan_id: str):
    '''
    Download the OpenVAS report for a finished scan, build the normalized
    vulnerability payload (CVE-only findings), and upload it to Google Drive.

    The uploaded JSON follows the OV1-MI data contract (schema_version 1.0)
    and is intended for consumption by the MI agent (Gabriel) for MISP ingestion.
    This endpoint is called by Jenkinsfile-scan after MrBenny delivery.

    Returns drive_file_id on success, or null when Drive is not configured
    or the scan has not yet been pushed to MrBenny.
    '''
    record = get_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not record.mrbenny_pushed:
        return {
            "drive_file_id": None,
            "skipped": True,
            "reason": "scan not yet pushed to MrBenny",
        }

    if record.report_id is None:
        return {
            "drive_file_id": None,
            "skipped": True,
            "reason": "report_id not available",
        }

    try:
        report_xml = openvas.get_report(record.report_id)
    except Exception as exc:
        logger.error(
            "upload_drive: failed to fetch report for scan %s: %s", scan_id, exc
        )
        raise HTTPException(
            status_code=500, detail=f"Could not fetch OpenVAS report: {exc}"
        )

    file_id = google_drive_client.upload_scan_payload(
        scan_id=record.scan_id,
        asset_id=record.asset_id,
        hostname=record.hostname,
        ip_address=record.ip_address,
        report_id=record.report_id,
        mrbenny_device_ids=record.mrbenny_device_ids,
        report_xml=report_xml,
    )

    return {"drive_file_id": file_id, "skipped": file_id is None}