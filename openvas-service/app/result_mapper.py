"""
Result mapping utilities for the OV1 service.

This module transforms raw scan results into a normalized internal structure
used by the OV1 service. The mapped result can later be returned through the
API, stored in a database, or forwarded to external systems such as MISP.
"""


def build_mock_result(
    scan_id: str,
    asset_id: str,
    hostname: str,
    ip_address: str,
) -> dict:
    return {
        "scan_id": scan_id,
        "asset_id": asset_id,
        "hostname": hostname,
        "ip_address": ip_address,
        "summary": {
            "total_findings": 2,
            "high": 1,
            "medium": 1,
            "low": 0,
        },
        "findings": [
            {
                "title": "OpenSSH outdated version detected",
                "severity": "high",
                "description": "The detected OpenSSH version is outdated and may be affected by known vulnerabilities.",
                "cve": ["CVE-2023-38408"],
            },
            {
                "title": "HTTP security headers missing",
                "severity": "medium",
                "description": "The target web service does not return recommended HTTP security headers.",
                "cve": [],
            },
        ],
    }


def map_openvas_result(raw_result: dict, scan_id: str, asset_id: str, hostname: str, ip_address: str) -> dict:
    findings = raw_result.get("findings", [])

    high = sum(1 for finding in findings if finding.get("severity") == "high")
    medium = sum(1 for finding in findings if finding.get("severity") == "medium")
    low = sum(1 for finding in findings if finding.get("severity") == "low")

    return {
        "scan_id": scan_id,
        "asset_id": asset_id,
        "hostname": hostname,
        "ip_address": ip_address,
        "summary": {
            "total_findings": len(findings),
            "high": high,
            "medium": medium,
            "low": low,
        },
        "findings": findings,
    }