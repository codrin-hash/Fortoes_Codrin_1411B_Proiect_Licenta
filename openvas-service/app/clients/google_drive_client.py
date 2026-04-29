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
from datetime import datetime, timezone
from io import BytesIO

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


def upload_scan_payload(scan_id: str, payload: dict) -> str | None:
    '''
    Serialize payload to JSON and upload it to the configured Drive folder.
    The filename encodes the scan_id and UTC timestamp for traceability.
    Returns the Drive file ID on success, or None if upload is skipped or fails.
    '''
    folder_id = settings.google_drive_folder_id
    if not folder_id:
        logger.warning(
            "upload_scan_payload: GOOGLE_DRIVE_FOLDER_ID is not set — skipping upload"
        )
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"ov1-scan-{scan_id}-{timestamp}.json"

    try:
        service = _get_service()
        content = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        media = MediaIoBaseUpload(BytesIO(content), mimetype="application/json")

        file_metadata = {
            "name": filename,
            "parents": [folder_id],
        }

        uploaded = (
            service.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )

        file_id = uploaded.get("id")
        logger.info(
            "upload_scan_payload: scan=%s uploaded as '%s' (file_id=%s)",
            scan_id,
            filename,
            file_id,
        )
        return file_id

    except Exception as exc:
        logger.error(
            "upload_scan_payload: failed to upload scan=%s — %s", scan_id, exc
        )
        return None