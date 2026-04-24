'''
OpenVAS result mapper for the OV1 service.

Transforms raw OpenVAS XML reports into MrBennyObservation objects
ready to be sent to MrBenny via POST /api/v1/ingest/data.

One observation is produced per scanned host, containing identifiers
(IP, MAC, hostname, openvas_host_id), attributes (OS), and a list of
vulnerability findings with severity derived from the CVSS score.

The mapper is intentionally stateless: it receives the parsed XML tree and
returns a list of observations. All side effects (sending, journaling) are
handled by the caller.

'''

import logging
from typing import Optional
from xml.etree.ElementTree import Element

from app.models.mr_benny_models import (
    MrBennyFinding,
    MrBennyIdentifier,
    MrBennyObservation,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVSS score -> severity class string
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> str:
    '''
    Convert a numeric CVSS score to a severity class string.

    Uses standard Greenbone / NVD thresholds. Negative or NaN
    values are not expected but are treated as "log".
    '''
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    else:
        return "log"


# ---------------------------------------------------------------------------
# XML helper
# ---------------------------------------------------------------------------

def _extract_text(element: Optional[Element], path: str) -> Optional[str]:
    '''
    Return the stripped text of an XML sub-element at the given XPath path,
    or None if the element is missing or has no text content.
    '''
    if element is None:
        return None
    node = element.find(path)
    if node is None or not node.text:
        return None
    return node.text.strip()


# ---------------------------------------------------------------------------
# Finding parser
# ---------------------------------------------------------------------------

def _parse_findings(result_elements: list[Element]) -> list[MrBennyFinding]:
    '''
    Build a list of MrBennyFinding objects from a pre-filtered list of
    <result> XML elements belonging to a single host.

    Each <result> represents one vulnerability. The primary code is the
    first CVE reference found in <nvt><refs>; the NVT OID is used as
    fallback when no CVE is available. The numeric CVSS score is converted
    to a severity class string via _cvss_to_severity().
    '''
    findings: list[MrBennyFinding] = []

    for result in result_elements:
        nvt = result.find("nvt")
        if nvt is None:
            # Results without <nvt> are not vulnerabilities — skip
            continue

        # Prefer <result><name>; fall back to <nvt><name>
        title = (
            _extract_text(result, "name")
            or _extract_text(nvt, "name")
            or "Unknown"
        )

        oid = nvt.get("oid", "")

        # Convert numeric CVSS score to severity class string
        severity_text = _extract_text(result, "severity")
        try:
            cvss_score = float(severity_text) if severity_text else 0.0
        except ValueError:
            cvss_score = 0.0
        severity_class = _cvss_to_severity(cvss_score)

        # Use the first CVE as the primary code; fall back to NVT OID
        cve_refs = [
            ref.get("id", "")
            for ref in nvt.findall("refs/ref")
            if ref.get("type", "") == "cve" and ref.get("id", "")
        ]
        code = cve_refs[0] if cve_refs else (oid or "unknown")

        findings.append(MrBennyFinding(
            finding_type="vulnerability",
            code=code,
            severity=severity_class,
            title=title,
            description=_extract_text(result, "description"),
            port=_extract_text(result, "port"),
            nvt_oid=oid if oid else None,
        ))

    return findings


# ---------------------------------------------------------------------------
# Host detail extractor
# ---------------------------------------------------------------------------

def _extract_host_details(host_el: Element) -> dict:
    '''
    Parse <detail> and <asset> children of a <host> element to extract
    additional identifiers (MAC, hostname, fqdn, openvas_host_id),
    host attributes (OS), and the agent_local_ref string.

    The IP address is intentionally excluded here and added by the caller
    as it is always the first mandatory identifier.
    '''
    extra_identifiers: list[MrBennyIdentifier] = []
    attributes: dict = {}
    openvas_host_id: Optional[str] = None

    for detail in host_el.findall("detail"):
        name = _extract_text(detail, "name")
        value = _extract_text(detail, "value")
        if not name or not value:
            continue

        name_lower = name.lower()

        if name.upper() == "MAC":
            extra_identifiers.append(MrBennyIdentifier(type="mac", value=value))
        elif name_lower in ("hostname", "fqdn"):
            extra_identifiers.append(MrBennyIdentifier(type=name_lower, value=value))
        elif name_lower in ("best_os_txt", "os"):
            # OpenVAS stores the OS guess under "best_os_txt"
            attributes["os"] = value
        elif name_lower == "traceroute":
            pass  # Not relevant for MrBenny — skip

    # openvas_host_id lives in <asset asset_id="...">, not in <detail>
    asset_el = host_el.find("asset")
    if asset_el is not None:
        host_asset_id = asset_el.get("asset_id") or asset_el.get("id")
        if host_asset_id:
            openvas_host_id = host_asset_id
            extra_identifiers.append(
                MrBennyIdentifier(type="openvas_host_id", value=host_asset_id)
            )

    return {
        "identifiers": extra_identifiers,
        "attributes": attributes if attributes else None,
        # Format matches the reference JSON: "openvas-host-<id>"
        "agent_local_ref": f"openvas-host-{openvas_host_id}" if openvas_host_id else None,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def map_report_to_observations(
    report_xml: Element,
    scan_id: str,
) -> list[MrBennyObservation]:
    '''
    Convert an OpenVAS report XML element into a list of MrBennyObservation
    objects, one per scanned host.

    GMP wraps the report in nested <report> tags:
        <get_reports_response><report><report>
    This function navigates to the innermost <report> containing the
    actual <host> and <results/result> elements.

    Two extraction paths:
        1. Primary  — iterates over <host> elements (normal complete reports)
        2. Fallback — infers hosts from <result><host> when no <host>
                      elements exist (partial or minimal reports)
    '''
    # Navigate to the innermost <report> with actual scan data
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

    # --- Primary path: iterate over <host> elements ---
    for host_el in report.findall("host"):
        ip = _extract_text(host_el, "ip")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        # IP is always the first mandatory identifier
        identifiers: list[MrBennyIdentifier] = [
            MrBennyIdentifier(type="ip", value=ip)
        ]

        host_details = _extract_host_details(host_el)
        identifiers.extend(host_details["identifiers"])

        # Collect all <result> elements for this host IP
        host_results = [
            r for r in report.findall("results/result")
            if _extract_text(r, "host") == ip
        ]

        findings = _parse_findings(host_results)

        observations.append(MrBennyObservation(
            observation_ref=f"ov-{scan_id}-host-{host_index}",
            agent_local_ref=host_details["agent_local_ref"],
            identifiers=identifiers,
            attributes=host_details["attributes"],
            findings=findings if findings else None,
        ))
        host_index += 1

    # --- Fallback path: infer hosts from <results> ---
    if not observations:
        logger.info(
            "No <host> elements found in report; "
            "falling back to results-based host extraction"
        )
        for result_el in report.findall("results/result"):
            ip = _extract_text(result_el, "host")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            host_results = [
                r for r in report.findall("results/result")
                if _extract_text(r, "host") == ip
            ]
            findings = _parse_findings(host_results)

            # No <detail> or <asset> data available in fallback mode
            observations.append(MrBennyObservation(
                observation_ref=f"ov-{scan_id}-host-{host_index}",
                agent_local_ref=None,
                identifiers=[MrBennyIdentifier(type="ip", value=ip)],
                attributes=None,
                findings=findings if findings else None,
            ))
            host_index += 1

    logger.info(
        "map_report_to_observations: produced %d observation(s) for scan %s",
        len(observations),
        scan_id,
    )
    return observations