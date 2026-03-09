"""
Security utilities for the OV1 service.

This module implements a simple authentication mechanism for the API using
a static Bearer token.
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

bearer_scheme = HTTPBearer(auto_error=False)


def require_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),) -> None:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header is required")

    if credentials.scheme != "Bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")

    if credentials.credentials != settings.service_api_token:
        raise HTTPException(status_code=403, detail="Invalid token")