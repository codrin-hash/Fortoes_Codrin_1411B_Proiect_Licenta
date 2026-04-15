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

        # MrBenny API base URL
        # Example: https://projects.opti.ro/tuiasimrbenny
        self.mrbenny_base_url = os.getenv("MRBENNY_BASE_URL", "")

        # Mode A — static dev key (fallback, used only if B1 session is unavailable)
        self.mrbenny_api_key = os.getenv("MRBENNY_API_KEY")

        # Mode B1 — session-based authentication
        # The install token is generated once by the admin and stored here.
        # At startup the service exchanges it for a session token via
        # POST /api/v1/auth/session and uses that token for all ingest calls.
        self.mrbenny_install_token = os.getenv("MRBENNY_INSTALL_TOKEN")
        self.mrbenny_hardware_uuid = os.getenv(
            "MRBENNY_HARDWARE_UUID", "ov1-codrin-licenta-2026"
        )
        self.mrbenny_agent_version = os.getenv("MRBENNY_AGENT_VERSION", "0.1.0")
        self.mrbenny_host_label = os.getenv("MRBENNY_HOST_LABEL", "ov1-service")

        # How often (seconds) the background task polls OpenVAS for
        # completed scans and pushes results to MrBenny
        self.poll_interval_seconds = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))

    def validate(self) -> None:
        """
        Validate required settings at startup.

        OpenVAS credentials are mandatory. MrBenny settings are validated
        with warnings only — the service can still accept scan requests
        without them, queuing results until MrBenny is reachable.

        B1 mode requires MRBENNY_INSTALL_TOKEN. If absent, the service
        falls back to Mode A using MRBENNY_API_KEY.
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
        if not self.mrbenny_install_token:
            logger.warning(
                "MRBENNY_INSTALL_TOKEN is not set — falling back to Mode A (api key)"
            )
        if not self.mrbenny_install_token and not self.mrbenny_api_key:
            logger.warning(
                "Neither MRBENNY_INSTALL_TOKEN nor MRBENNY_API_KEY is set — "
                "MrBenny requests will fail"
            )


settings = Settings()