"""
OpenVAS client for the OV1 service.

This module implements the communication layer between the OV1 service
and the OpenVAS (GVM) vulnerability scanner using the Greenbone
Management Protocol (GMP).

The client is responsible for creating scan targets, creating scan tasks,
starting scans, retrieving task status, and downloading scan reports.
"""

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

from app.config import settings


class OpenVASClient:
    def __init__(self):
        self.host = settings.openvas_host
        self.port = settings.openvas_port
        self.username = settings.openvas_username
        self.password = settings.openvas_password

    def _connect(self) -> Gmp:
        connection = TLSConnection(hostname=self.host, port=self.port)
        gmp = Gmp(connection=connection, transform=EtreeTransform())

        gmp.connect()
        gmp.authenticate(self.username, self.password)

        return gmp

    def create_target(self, name: str, host: str) -> str:
        gmp = self._connect()

        try:
            response = gmp.create_target(name=name, hosts=[host])
            return response.get("id")
        finally:
            gmp.disconnect()

    def create_task(self, name: str, target_id: str, scan_config_id: str) -> str:
        gmp = self._connect()

        try:
            response = gmp.create_task(
                name=name,
                config_id=scan_config_id,
                target_id=target_id,
            )
            return response.get("id")
        finally:
            gmp.disconnect()

    def start_task(self, task_id: str) -> None:
        gmp = self._connect()

        try:
            gmp.start_task(task_id)
        finally:
            gmp.disconnect()

    def get_task_status(self, task_id: str) -> dict:
        gmp = self._connect()

        try:
            task = gmp.get_task(task_id=task_id)

            status = task.findtext(".//task/status")
            progress = task.findtext(".//task/progress")

            if progress is not None:
                progress = int(progress)

            return {
                "status": status,
                "progress": progress,
            }

        finally:
            gmp.disconnect()

    def get_report(self, report_id: str):
        gmp = self._connect()

        try:
            report = gmp.get_report(report_id=report_id, details=True)
            return report
        finally:
            gmp.disconnect()