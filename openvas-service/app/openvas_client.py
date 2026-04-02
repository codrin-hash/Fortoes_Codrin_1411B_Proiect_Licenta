"""
OpenVAS client for the OV1 service.

This module implements the communication layer between the OV1 service
and the OpenVAS (GVM) vulnerability scanner using the Greenbone
Management Protocol (GMP).

The client is responsible for creating scan targets, creating scan tasks,
starting scans, retrieving task status, retrieving the report ID from a
completed task, and downloading scan reports.
"""

import logging
import uuid

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from app.config import settings

logger = logging.getLogger(__name__)

# Standard Greenbone built-in IDs (present in every installation)
# Port list: "All IANA assigned TCP and UDP"
DEFAULT_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
# Scan config: "Full and Fast"
DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
# Scanner: "OpenVAS Default"
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"


class OpenVASClient:
    def __init__(self):
        self.socket_path = settings.openvas_socket_path
        self.username = settings.openvas_username
        self.password = settings.openvas_password
        self.transform = EtreeCheckCommandTransform()

    def _get_connection(self) -> UnixSocketConnection:
        return UnixSocketConnection(path=self.socket_path)

    def create_target(self, name: str, host: str) -> str:
        """
        Create a scan target in OpenVAS for the given host.

        A short UUID suffix is appended to the name to guarantee uniqueness
        across repeated scans for the same host — OpenVAS rejects duplicate
        target names with a 400 error.

        Args:
            name: Human-readable base name (e.g. "hostname-ip")
            host: IP address of the host to scan

        Returns:
            The OpenVAS target ID (UUID string)
        """
        connection = self._get_connection()

        # Append a short UUID to guarantee uniqueness across repeated scans
        unique_name = f"{name}-{uuid.uuid4().hex[:8]}"

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.create_target(
                name=unique_name,
                hosts=[host],
                port_list_id=DEFAULT_PORT_LIST_ID,
            )
            return response.get("id")

    def create_task(self, name: str, target_id: str, scan_config_id: str) -> str:
        """
        Create a scan task in OpenVAS.

        A short UUID suffix is appended to the name to guarantee uniqueness
        across repeated scans. The built-in OpenVAS scanner is always used.

        Args:
            name:           Human-readable base name for the task
            target_id:      OpenVAS target ID returned by create_target()
            scan_config_id: OpenVAS scan configuration ID

        Returns:
            The OpenVAS task ID (UUID string)
        """
        connection = self._get_connection()

        # Append a short UUID to guarantee uniqueness across repeated scans
        unique_name = f"{name}-{uuid.uuid4().hex[:8]}"

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.create_task(
                name=unique_name,
                config_id=scan_config_id,
                target_id=target_id,
                scanner_id=DEFAULT_SCANNER_ID,
            )
            return response.get("id")

    def start_task(self, task_id: str) -> None:
        """
        Start execution of an existing OpenVAS task.

        Args:
            task_id: OpenVAS task ID returned by create_task()
        """
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            gmp.start_task(task_id)

    def get_task_status(self, task_id: str) -> dict:
        """
        Retrieve the current status and progress of an OpenVAS task.

        Returns:
            A dict with keys:
                status   : string (e.g. "Running", "Done", "Stopped")
                progress : int percentage 0-100, or None if not available
        """
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            task = gmp.get_task(task_id=task_id)

            status = task.findtext(".//task/status")
            progress = task.findtext(".//task/progress")

            if progress is not None:
                try:
                    progress = int(progress)
                except ValueError:
                    progress = None

            return {
                "status": status,
                "progress": progress,
            }

    def get_report_id_from_task(self, task_id: str) -> str | None:
        """
        Return the report ID of the last completed report for a task.

        OpenVAS stores the last report reference inside the task XML:
            <task><last_report><report id="..."/></last_report></task>

        Returns None if the task has not produced a report yet.
        """
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            task = gmp.get_task(task_id=task_id)

            report_el = task.find(".//task/last_report/report")
            if report_el is None:
                logger.debug(
                    "get_report_id_from_task: no last_report found for task %s", task_id
                )
                return None

            return report_el.get("id")

    def get_report(self, report_id: str):
        """
        Download the full report XML for a given report ID.

        Returns the raw lxml Element from GMP (get_reports_response).
        The result_mapper module knows how to navigate this structure.
        """
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            return gmp.get_report(report_id=report_id, details=True)