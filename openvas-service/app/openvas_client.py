"""
OpenVAS client for the OV1 service.

This module implements the communication layer between the OV1 service
and the OpenVAS (GVM) vulnerability scanner using the Greenbone
Management Protocol (GMP).

The client is responsible for creating scan targets, creating scan tasks,
starting scans, retrieving task status, and downloading scan reports.
"""

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from app.config import settings


class OpenVASClient:
    def __init__(self):
        self.socket_path = settings.openvas_socket_path
        self.username = settings.openvas_username
        self.password = settings.openvas_password
        self.transform = EtreeCheckCommandTransform()

    def _get_connection(self) -> UnixSocketConnection:
        return UnixSocketConnection(path=self.socket_path)

    def create_target(self, name: str, host: str) -> str:
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.create_target(name=name, hosts=[host])
            return response.get("id")

    def create_task(self, name: str, target_id: str, scan_config_id: str) -> str:
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.create_task(
                name=name,
                config_id=scan_config_id,
                target_id=target_id,
            )
            return response.get("id")

    def start_task(self, task_id: str) -> None:
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            gmp.start_task(task_id)

    def get_task_status(self, task_id: str) -> dict:
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            task = gmp.get_task(task_id=task_id)

            status = task.findtext(".//task/status")
            progress = task.findtext(".//task/progress")

            if progress is not None:
                progress = int(progress)

            return {
                "status": status,
                "progress": progress,
            }

    def get_report(self, report_id: str):
        connection = self._get_connection()

        with GMP(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.username, self.password)
            return gmp.get_report(report_id=report_id, details=True)