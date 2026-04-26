'''
Unit tests for the _cvss_to_severity() helper in result_mapper.

Each test covers one threshold boundary using Greenbone / NVD ranges:
    >= 9.0  -> critical
    >= 7.0  -> high
    >= 4.0  -> medium
    >  0.0  -> low
    == 0.0  -> log
'''

import pytest

from app.core.result_mapper import _cvss_to_severity


class TestCvssToSeverity:

    def test_score_at_critical_threshold(self):
        assert _cvss_to_severity(9.0) == "critical"

    def test_score_above_critical_threshold(self):
        assert _cvss_to_severity(9.8) == "critical"

    def test_score_at_high_threshold(self):
        assert _cvss_to_severity(7.0) == "high"

    def test_score_within_high_range(self):
        assert _cvss_to_severity(8.5) == "high"

    def test_score_at_medium_threshold(self):
        assert _cvss_to_severity(4.0) == "medium"

    def test_score_within_medium_range(self):
        assert _cvss_to_severity(5.8) == "medium"

    def test_score_above_zero_is_low(self):
        assert _cvss_to_severity(2.1) == "low"

    def test_score_at_minimum_low(self):
        assert _cvss_to_severity(0.1) == "low"

    def test_score_zero_is_log(self):
        assert _cvss_to_severity(0.0) == "log"

    def test_score_negative_is_log(self):
        '''Negative CVSS values are not standard but must not crash.'''
        assert _cvss_to_severity(-1.0) == "log"