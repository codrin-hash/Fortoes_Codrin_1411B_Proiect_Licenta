# Credentials configuration for the OpenVAS service

import os


class Settings:
    def __init__(self):
        self.service_port = int(os.getenv("SERVICE_PORT"))
        self.service_api_token = os.getenv("SERVICE_API_TOKEN")

        self.openvas_socket_path = os.getenv("OPENVAS_SOCKET_PATH")
        self.openvas_username = os.getenv("OPENVAS_USERNAME")
        self.openvas_password = os.getenv("OPENVAS_PASSWORD")

        self.misp_url = os.getenv("MISP_URL")
        self.misp_api_key = os.getenv("MISP_API_KEY")
        self.misp_verify_tls = os.getenv("MISP_VERIFY_TLS")

    def validate(self) -> None:
        if not self.service_api_token:
            raise ValueError("Service API Token is missing")
        if not self.openvas_username:
            raise ValueError("OpenVAS username is missing")
        if not self.openvas_password:
            raise ValueError("OpenVAS password is missing")

settings = Settings()
