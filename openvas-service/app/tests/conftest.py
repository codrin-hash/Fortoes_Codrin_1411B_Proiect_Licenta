'''
Shared pytest fixtures for the OV1 test suite.

Provides parsed XML elements — either loaded from tests/fixtures/ files
or built inline — so individual test modules do not need to repeat
XML parsing logic.
'''

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_R = '</' + 'r' + 'esult>'   # </r> built without triggering ET mismatch warnings


@pytest.fixture
def report_full_xml() -> ET.Element:
    '''
    Parsed XML for a complete report: one host with MAC, hostname, OS,
    asset_id, and three vulnerability findings (critical / medium / low).
    '''
    return ET.parse(FIXTURES_DIR / "report_full.xml").getroot()


@pytest.fixture
def report_no_host_xml() -> ET.Element:
    '''
    Report with no <host> elements — only bare <results/result> entries.
    Exercises the fallback host-extraction path.
    '''
    xml_str = ''.join([
        '<get_reports_response><report id="r1"><report id="r1">',
        '<results>',
        '<result id="res-1">',
        '<n>Fallback Finding</n>',
        '<host>192.168.1.1</host>',
        '<port>80/tcp</port>',
        '<severity>7.5</severity>',
        '<description>Fallback path finding.</description>',
        '<nvt oid="1.3.6.1.4.1.25623.1.0.000001">',
        '<n>Fallback Check</n>',
        '<refs><ref type="cve" id="CVE-2020-11111"/></refs>',
        '</nvt>',
        _R,
        '</results>',
        '</report></report></get_reports_response>',
    ])
    return ET.fromstring(xml_str)


@pytest.fixture
def report_empty_xml() -> ET.Element:
    '''Report with no hosts and no results — must produce zero observations.'''
    xml_str = (
        '<get_reports_response>'
        '<report id="empty"><report id="empty"></report></report>'
        '</get_reports_response>'
    )
    return ET.fromstring(xml_str)


@pytest.fixture
def report_malformed_xml() -> ET.Element:
    '''
    A bare <report> element with no nesting and no results.
    Simulates a truncated or unexpected document structure.
    '''
    return ET.fromstring('<report id="bare"></report>')