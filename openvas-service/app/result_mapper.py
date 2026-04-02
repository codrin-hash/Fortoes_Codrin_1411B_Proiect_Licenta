"""
OpenVAS result mapper for the OV1 service.

This module transforms raw OpenVAS scan report XML (as an lxml ElementTree)
into MrBenny ingest observations.

Each scanned host becomes one MrBennyObservation. Identifiers are extracted
from the host's IP address, MAC address (if present in asset details), and
hostname. Detected vulnerabilities are attached as a free-form list that
MrBenny stores alongside the observation.

The mapper is intentionally stateless: it receives the parsed XML tree and
returns a list of observations. All side effects (sending, journaling) are
handled by the caller.

"""

import logging
from typing import Optional
from xml.etree.ElementTree import Element

from app.mr_benny_models import MrBennyIdentifier, MrBennyObservation

logger = logging.getLogger(__name__)


def _extract_text(element: Optional[Element], path: str) -> Optional[str]:
    """Return stripped text at XPath path, or None if missing/empty."""
    if element is None:
        return None
    node = element.find(path)
    if node is None or not node.text:
        return None
    return node.text.strip()


def _parse_vulnerabilities(result_elements: list[Element]) -> list[dict]:
    """
    Extract vulnerability entries from a list of <result> XML elements.

    Each <result> in the OpenVAS report represents one finding on one host.
    We extract the fields most relevant for MrBenny / MISP correlation.
    """
    vulnerabilities = []

    for result in result_elements:
        nvt = result.find("nvt")
        if nvt is None:
            continue

        name = _extract_text(result, "name") or _extract_text(nvt, "name") or "Unknown"
        oid = nvt.get("oid", "")
        severity_text = _extract_text(result, "severity")
        port = _extract_text(result, "port")
        description = _extract_text(result, "description")
        threat = _extract_text(result, "threat")

        # CVE references
        cve_refs = [
            ref.get("id", "")
            for ref in nvt.findall("refs/ref")
            if ref.get("type", "") == "cve"
        ]

        entry = {
            "name": name,
            "nvt_oid": oid,
            "severity": float(severity_text) if severity_text else None,
            "threat": threat,
            "port": port,
            "cve_refs": cve_refs,
            "description": description,
        }

        # drop None values to keep payload clean
        entry = {k: v for k, v in entry.items() if v is not None}
        vulnerabilities.append(entry)

    return vulnerabilities


def map_report_to_observations(
    report_xml: Element,
    scan_id: str,
) -> list[MrBennyObservation]:
    """
    Convert a parsed OpenVAS report XML element into a list of
    MrBennyObservation objects, one per scanned host.

    Args:
        report_xml: The root Element from gmp.get_report(), which is the
                    <get_reports_response> or the inner <report> element.
        scan_id:    Internal OV1 scan identifier, used to build stable
                    observation_ref values.

    Returns:
        A list of MrBennyObservation, possibly empty if no hosts found.
    """
    # GMP wraps the actual report inside <get_reports_response><report><report>
    # Try to find the innermost <report> that contains <host> elements.
    report = report_xml
    if report.tag == "get_reports_response":
        report = report.find("report")
    if report is not None and report.find("report") is not None:
        report = report.find("report")

    if report is None:
        logger.warning("map_report_to_observations: could not locate <report> element")
        return []

    observations: list[MrBennyObservation] = []
    host_index = 0
    seen_ips: set[str] = set()

    # Iterate over <host> elements inside the report
    for host_el in report.findall("host"):
        ip = _extract_text(host_el, "ip")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        identifiers: list[MrBennyIdentifier] = [
            MrBennyIdentifier(type="ip", value=ip)
        ]

        # MAC address and hostname — present in <detail> children
        for detail in host_el.findall("detail"):
            detail_name = _extract_text(detail, "name")
            detail_value = _extract_text(detail, "value")
            if not detail_name or not detail_value:
                continue
            if detail_name.upper() == "MAC":
                identifiers.append(
                    MrBennyIdentifier(type="mac", value=detail_value)
                )
            elif detail_name.lower() in ("hostname", "fqdn"):
                identifiers.append(
                    MrBennyIdentifier(type=detail_name.lower(), value=detail_value)
                )

        # Collect results (vulnerabilities) for this host
        host_results = [
            r for r in report.findall("results/result")
            if _extract_text(r, "host") == ip
        ]

        vulns = _parse_vulnerabilities(host_results)

        severities = [v["severity"] for v in vulns if "severity" in v]
        scan_summary = {
            "total_findings": len(vulns),
            "max_severity": max(severities) if severities else 0.0,
        }

        observations.append(MrBennyObservation(
            observation_ref=f"scan-{scan_id}-host-{host_index}",
            identifiers=identifiers,
            vulnerabilities=vulns if vulns else None,
            scan_summary=scan_summary,
        ))
        host_index += 1

    # Fallback: if no <host> elements, infer hosts from <results>
    if not observations:
        logger.info(
            "No <host> elements found in report; falling back to results-based extraction"
        )
        for result_el in report.findall("results/result"):
            ip = _extract_text(result_el, "host")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            identifiers = [MrBennyIdentifier(type="ip", value=ip)]
            host_results = [
                r for r in report.findall("results/result")
                if _extract_text(r, "host") == ip
            ]
            vulns = _parse_vulnerabilities(host_results)
            severities = [v["severity"] for v in vulns if "severity" in v]

            observations.append(MrBennyObservation(
                observation_ref=f"scan-{scan_id}-host-{host_index}",
                identifiers=identifiers,
                vulnerabilities=vulns if vulns else None,
                scan_summary={
                    "total_findings": len(vulns),
                    "max_severity": max(severities) if severities else 0.0,
                },
            ))
            host_index += 1

    logger.info(
        "map_report_to_observations: produced %d observation(s) for scan %s",
        len(observations),
        scan_id,
    )
    return observations