# Credentials and configuration for the OV1 OpenVAS service

import logging
import os

logger = logging.getLogger(__name__)


class Settings:
    def __init__(self):
        self.service_port = int(os.getenv("SERVICE_PORT", "8081"))
        self.service_api_token = os.getenv("SERVICE_API_TOKEN")

        self.openvas_socket_path = os.getenv(
            "OPENVAS_SOCKET_PATH", "/run/gvmd/gvmd.sock"
        )
        self.openvas_username = os.getenv("OPENVAS_USERNAME")
        self.openvas_password = os.getenv("OPENVAS_PASSWORD")

        self.misp_url = os.getenv("MISP_URL")
        self.misp_api_key = os.getenv("MISP_API_KEY")
        self.misp_verify_tls = os.getenv("MISP_VERIFY_TLS", "true").lower() == "true"

        # MrBenny API (Mode A — static key)
        # Base URL example: https://projects.opti.ro/tuiasimrbenny
        self.mrbenny_base_url = os.getenv("MRBENNY_BASE_URL", "")
        self.mrbenny_api_key = os.getenv("MRBENNY_API_KEY", "tuiasi-dev")

        # How often (seconds) the background task polls OpenVAS for
        # completed scans and pushes results to MrBenny
        self.poll_interval_seconds = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))

    def validate(self) -> None:
        """
        Validate required settings at startup.

        OpenVAS credentials are mandatory — without them the service
        cannot do anything useful.

        MrBenny settings are warned about but do NOT block startup,
        so the service can still accept scan requests even if MrBenny
        is not yet configured (scans will be queued and pushed once
        MRBENNY_BASE_URL is set and the service is restarted).
        """
        errors = []

        if not self.service_api_token:
            errors.append("SERVICE_API_TOKEN is missing")
        if not self.openvas_username:
            errors.append("OPENVAS_USERNAME is missing")
        if not self.openvas_password:
            errors.append("OPENVAS_PASSWORD is missing")

        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")

        if not self.mrbenny_base_url:
            logger.warning(
                "MRBENNY_BASE_URL is not set — scan results will NOT be pushed to MrBenny"
            )
        if not self.mrbenny_api_key:
            logger.warning(
                "MRBENNY_API_KEY is not set — MrBenny requests will fail"
            )


settings = Settings()