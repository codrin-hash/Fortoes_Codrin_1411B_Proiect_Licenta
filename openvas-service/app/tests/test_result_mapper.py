'''
Unit tests for result_mapper.map_report_to_observations().

Tests cover:
  - Normal path (full report with <host> elements)
  - Identifier extraction (IP, MAC, hostname, openvas_host_id)
  - Attribute extraction (OS)
  - Finding parsing (CVE code, severity, fallback to NVT OID)
  - Fallback path (no <host> elements, infer from <results>)
  - Edge cases (empty report, bare <report> element)
  - observation_ref format
  - agent_local_ref format
'''

import pytest

from app.core.result_mapper import map_report_to_observations
from app.models.mr_benny_models import MrBennyObservation


SCAN_ID = "test-scan-abc123"


class TestNormalPath:
    '''Tests using the full report fixture (one host, three findings).'''

    def test_produces_one_observation_per_host(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        assert len(obs) == 1

    def test_ip_is_first_identifier(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        first_id = obs[0].identifiers[0]
        assert first_id.type == "ip"
        assert first_id.value == "10.0.0.5"

    def test_mac_identifier_extracted(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        types = {i.type: i.value for i in obs[0].identifiers}
        assert "mac" in types
        assert types["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_hostname_identifier_extracted(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        types = {i.type: i.value for i in obs[0].identifiers}
        assert "hostname" in types
        assert types["hostname"] == "pc-lab-01"

    def test_openvas_host_id_extracted(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        types = {i.type: i.value for i in obs[0].identifiers}
        assert "openvas_host_id" in types
        assert types["openvas_host_id"] == "host-asset-42"

    def test_os_attribute_extracted(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        assert obs[0].attributes is not None
        assert obs[0].attributes.get("os") == "Linux 4.15"

    def test_agent_local_ref_format(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        assert obs[0].agent_local_ref == "openvas-host-host-asset-42"

    def test_observation_ref_format(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        assert obs[0].observation_ref == f"ov-{SCAN_ID}-host-0"

    def test_three_findings_parsed(self, report_full_xml):
        obs = map_report_to_observations(report_full_xml, SCAN_ID)
        assert obs[0].findings is not None
        assert len(obs[0].findings) == 3


class TestFindingDetails:
    '''Tests for individual finding fields within the observations.'''

    def _findings(self, xml):
        obs = map_report_to_observations(xml, SCAN_ID)
        return obs[0].findings

    def test_critical_finding_has_cve_code(self, report_full_xml):
        findings = self._findings(report_full_xml)
        critical = next(f for f in findings if f.severity == "critical")
        assert critical.code == "CVE-2021-44228"

    def test_critical_finding_severity(self, report_full_xml):
        findings = self._findings(report_full_xml)
        assert any(f.severity == "critical" for f in findings)

    def test_medium_finding_severity(self, report_full_xml):
        findings = self._findings(report_full_xml)
        assert any(f.severity == "medium" for f in findings)

    def test_low_finding_falls_back_to_nvt_oid(self, report_full_xml):
        '''
        When no CVE reference exists, code must be the NVT OID.
        '''
        findings = self._findings(report_full_xml)
        low = next(f for f in findings if f.severity == "low")
        assert low.code == "1.3.6.1.4.1.25623.1.0.999003"

    def test_finding_type_is_vulnerability(self, report_full_xml):
        findings = self._findings(report_full_xml)
        for f in findings:
            assert f.finding_type == "vulnerability"

    def test_finding_port_extracted(self, report_full_xml):
        findings = self._findings(report_full_xml)
        critical = next(f for f in findings if f.severity == "critical")
        assert critical.port == "8080/tcp"

    def test_finding_description_extracted(self, report_full_xml):
        findings = self._findings(report_full_xml)
        critical = next(f for f in findings if f.severity == "critical")
        assert critical.description is not None
        assert len(critical.description) > 0


class TestFallbackPath:
    '''Tests for the fallback path where no <host> elements are present.'''

    def test_fallback_produces_observation(self, report_no_host_xml):
        obs = map_report_to_observations(report_no_host_xml, SCAN_ID)
        assert len(obs) == 1

    def test_fallback_ip_extracted(self, report_no_host_xml):
        obs = map_report_to_observations(report_no_host_xml, SCAN_ID)
        assert obs[0].identifiers[0].type == "ip"
        assert obs[0].identifiers[0].value == "192.168.1.1"

    def test_fallback_no_agent_local_ref(self, report_no_host_xml):
        obs = map_report_to_observations(report_no_host_xml, SCAN_ID)
        assert obs[0].agent_local_ref is None

    def test_fallback_finding_code(self, report_no_host_xml):
        obs = map_report_to_observations(report_no_host_xml, SCAN_ID)
        assert obs[0].findings is not None
        assert obs[0].findings[0].code == "CVE-2020-11111"


class TestEdgeCases:
    '''Tests for empty or unusual report structures.'''

    def test_empty_report_returns_empty_list(self, report_empty_xml):
        obs = map_report_to_observations(report_empty_xml, SCAN_ID)
        assert obs == []

    def test_malformed_report_returns_empty_list(self, report_malformed_xml):
        '''A bare <report> with no results should not crash.'''
        obs = map_report_to_observations(report_malformed_xml, SCAN_ID)
        assert obs == []

    def test_duplicate_ip_produces_single_observation(self):
        '''
        When the same IP appears in two <host> elements (should not happen
        in practice), only the first is kept.
        '''
        xml_str = (
            '<get_reports_response><report id="r1"><report id="r1">'
            '<host><ip>10.0.0.1</ip></host>'
            '<host><ip>10.0.0.1</ip></host>'
            '<results></results>'
            '</report></report></get_reports_response>'
        )
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_str)
        obs = map_report_to_observations(root, SCAN_ID)
        assert len(obs) == 1