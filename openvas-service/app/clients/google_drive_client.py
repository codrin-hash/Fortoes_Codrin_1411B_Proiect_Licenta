'''
Uploads normalized vulnerability detection payloads to a shared Google Drive
folder, acting as an intermediate data exchange layer between OV1 and the MI
agent operated by Gabriel. Authentication relies on a service account, whose
credentials are supplied via the GOOGLE_SERVICE_ACCOUNT_JSON environment
variable (path to the JSON key file).
'''

import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from xml.etree.ElementTree import Element

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

from app.config import settings

logger = logging.getLogger(__name__)

_SCOPES = ["https://www.googleapis.com/auth/drive.file"]


def _get_service():
    '''
    Build and return an authenticated Google Drive API service client.
    Credentials are loaded from the path stored in GOOGLE_SERVICE_ACCOUNT_JSON.
    '''
    key_path = settings.google_service_account_json
    if not key_path or not os.path.isfile(key_path):
        raise RuntimeError(
            "GOOGLE_SERVICE_ACCOUNT_JSON is not set or the file does not exist"
        )
    creds = service_account.Credentials.from_service_account_file(
        key_path, scopes=_SCOPES
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def _text(element: Optional[Element], path: str) -> Optional[str]:
    '''Return stripped text of an XML sub-element, or None if absent.'''
    if element is None:
        return None
    node = element.find(path)
    if node is None or not node.text:
        return None
    return node.text.strip()


def _cvss_to_severity(score: float) -> str:
    '''Map a numeric CVSS score to a severity class string using NVD thresholds.'''
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "log"


def build_drive_payload(
    scan_id: str,
    asset_id: str,
    hostname: str,
    ip_address: str,
    report_id: Optional[str],
    mrbenny_device_ids: dict,
    report_xml: Optional[Element],
) -> dict:
    '''
    Construct the full normalized payload to be written to Google Drive.
    Extracts only findings that carry at least one CVE reference from the
    OpenVAS XML report. Findings without a CVE are silently discarded, as
    the MI agent (Gabriel) requires a CVE identifier for MISP ingestion.
    '''
    findings = []
    host_info = {
        "ip": ip_address,
        "hostname": hostname,
        "mac": None,
        "os": None,
        "mrbenny_device_id": mrbenny_device_ids.get(f"ip:{ip_address}"),
    }

    if report_xml is not None:
        report = report_xml
        if report.tag == "get_reports_response":
            report = report.find("report")
        if report is not None and report.find("report") is not None:
            report = report.find("report")

        if report is not None:
            # Extract MAC and OS from the matching <host> element
            for host_el in report.findall("host"):
                if _text(host_el, "ip") == ip_address:
                    for detail in host_el.findall("detail"):
                        name = _text(detail, "name") or ""
                        value = _text(detail, "value")
                        if not value:
                            continue
                        if name.upper() == "MAC":
                            host_info["mac"] = value
                        elif name.lower() in ("best_os_txt", "os"):
                            host_info["os"] = value
                    break

            # Extract findings with at least one CVE reference
            for result in report.findall("results/result"):
                if _text(result, "host") != ip_address:
                    continue

                nvt = result.find("nvt")
                if nvt is None:
                    continue

                cve_refs = [
                    ref.get("id", "")
                    for ref in nvt.findall("refs/ref")
                    if ref.get("type", "") == "cve" and ref.get("id", "")
                ]
                if not cve_refs:
                    # Findings without a CVE are excluded per the data contract
                    continue

                severity_text = _text(result, "severity")
                try:
                    cvss_score = float(severity_text) if severity_text else 0.0
                except ValueError:
                    cvss_score = 0.0

                findings.append({
                    "cve": cve_refs[0],
                    "title": _text(result, "name") or _text(nvt, "name") or "Unknown",
                    "severity": _cvss_to_severity(cvss_score),
                    "cvss_score": cvss_score,
                    "description": _text(result, "description"),
                })

    severity_counts = Counter(f["severity"] for f in findings)
    summary = {
        "total_with_cve": len(findings),
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
    }

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "openvas_report_id": report_id,
        },
        "host": host_info,
        "findings": findings,
        "summary": summary,
    }


def upload_scan_payload(
    scan_id: str,
    asset_id: str,
    hostname: str,
    ip_address: str,
    report_id: Optional[str],
    mrbenny_device_ids: dict,
    report_xml: Optional[Element],
) -> Optional[str]:
    '''
    Build the normalized payload and upload it to the configured Drive folder.
    The filename encodes the scan_id and UTC timestamp for traceability.
    Returns the Drive file ID on success, or None if upload is skipped or fails.
    '''
    folder_id = settings.google_drive_folder_id
    if not folder_id:
        logger.warning(
            "upload_scan_payload: GOOGLE_DRIVE_FOLDER_ID is not set — skipping upload"
        )
        return None

    payload = build_drive_payload(
        scan_id=scan_id,
        asset_id=asset_id,
        hostname=hostname,
        ip_address=ip_address,
        report_id=report_id,
        mrbenny_device_ids=mrbenny_device_ids,
        report_xml=report_xml,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"ov1-scan-{scan_id}-{timestamp}.json"

    try:
        service = _get_service()
        content = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        media = MediaIoBaseUpload(BytesIO(content), mimetype="application/json")

        file_metadata = {"name": filename, "parents": [folder_id]}
        uploaded = (
            service.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )

        file_id = uploaded.get("id")
        logger.info(
            "upload_scan_payload: scan=%s uploaded as '%s' (file_id=%s, findings=%d)",
            scan_id,
            filename,
            file_id,
            payload["summary"]["total_with_cve"],
        )
        return file_id

    except Exception as exc:
        logger.error(
            "upload_scan_payload: failed to upload scan=%s — %s", scan_id, exc
        )
        return None