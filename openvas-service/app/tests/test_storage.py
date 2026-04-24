'''
Unit tests for app.core.storage.

Tests cover the full lifecycle of a ScanRecord:
    create -> get -> update_status -> mark_mrbenny_pushed

Also verifies get_scans_pending_push filtering logic.
'''

import pytest

from app.core.storage import (
    SCAN_STORE,
    ScanRecord,
    create_scan_record,
    get_scan_record,
    get_scans_pending_push,
    mark_mrbenny_pushed,
    update_scan_status,
)


@pytest.fixture(autouse=True)
def clear_store():
    '''Reset the in-memory store before each test to prevent state leakage.'''
    SCAN_STORE.clear()
    yield
    SCAN_STORE.clear()


class TestCreateScanRecord:

    def test_returns_scan_record(self):
        rec = create_scan_record("asset-1", "host-a", "10.0.0.1", "tgt-1", "task-1")
        assert isinstance(rec, ScanRecord)

    def test_scan_id_is_assigned(self):
        rec = create_scan_record("asset-1", "host-a", "10.0.0.1", "tgt-1", "task-1")
        assert rec.scan_id is not None
        assert len(rec.scan_id) > 0

    def test_scan_id_is_unique(self):
        rec1 = create_scan_record("asset-1", "host-a", "10.0.0.1", "tgt-1", "task-1")
        rec2 = create_scan_record("asset-2", "host-b", "10.0.0.2", "tgt-2", "task-2")
        assert rec1.scan_id != rec2.scan_id

    def test_initial_status_is_created(self):
        rec = create_scan_record("asset-1", "host-a", "10.0.0.1", "tgt-1", "task-1")
        assert rec.status == "created"

    def test_stored_in_scan_store(self):
        rec = create_scan_record("asset-1", "host-a", "10.0.0.1", "tgt-1", "task-1")
        assert rec.scan_id in SCAN_STORE

    def test_fields_stored_correctly(self):
        rec = create_scan_record("asset-X", "host-X", "192.168.0.1", "tgt-X", "task-X")
        stored = SCAN_STORE[rec.scan_id]
        assert stored.asset_id == "asset-X"
        assert stored.hostname == "host-X"
        assert stored.ip_address == "192.168.0.1"
        assert stored.target_id == "tgt-X"
        assert stored.task_id == "task-X"


class TestGetScanRecord:

    def test_returns_record_for_known_id(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        found = get_scan_record(rec.scan_id)
        assert found is rec

    def test_returns_none_for_unknown_id(self):
        assert get_scan_record("does-not-exist") is None


class TestUpdateScanStatus:

    def test_status_updated(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Running", progress=45)
        assert SCAN_STORE[rec.scan_id].status == "Running"

    def test_progress_updated(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Running", progress=75)
        assert SCAN_STORE[rec.scan_id].progress == 75

    def test_report_id_set_when_provided(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Done", report_id="rpt-99")
        assert SCAN_STORE[rec.scan_id].report_id == "rpt-99"

    def test_report_id_not_overwritten_when_none(self):
        '''
        If report_id is already set and None is passed again,
        the existing value must be preserved.
        '''
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Done", report_id="rpt-99")
        update_scan_status(rec.scan_id, "Done")
        assert SCAN_STORE[rec.scan_id].report_id == "rpt-99"

    def test_returns_none_for_unknown_id(self):
        result = update_scan_status("no-such-id", "Done")
        assert result is None


class TestMarkMrbennyPushed:

    def test_pushed_flag_set(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        mark_mrbenny_pushed(rec.scan_id, {"ip:1.1.1.1": "dev_001"})
        assert SCAN_STORE[rec.scan_id].mrbenny_pushed is True

    def test_id_map_stored(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        id_map = {"ip:1.1.1.1": "dev_001", "mac:AA:BB:CC:DD:EE:FF": "dev_001"}
        mark_mrbenny_pushed(rec.scan_id, id_map)
        assert SCAN_STORE[rec.scan_id].mrbenny_device_ids == id_map

    def test_returns_none_for_unknown_id(self):
        result = mark_mrbenny_pushed("no-such-id", {})
        assert result is None


class TestGetScansPendingPush:

    def test_returns_done_not_pushed(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Done")
        pending = get_scans_pending_push()
        assert any(r.scan_id == rec.scan_id for r in pending)

    def test_excludes_already_pushed(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Done")
        mark_mrbenny_pushed(rec.scan_id, {})
        pending = get_scans_pending_push()
        assert not any(r.scan_id == rec.scan_id for r in pending)

    def test_excludes_scans_not_done(self):
        rec = create_scan_record("a", "h", "1.1.1.1", "t", "tk")
        update_scan_status(rec.scan_id, "Running")
        pending = get_scans_pending_push()
        assert not any(r.scan_id == rec.scan_id for r in pending)

    def test_returns_multiple_pending(self):
        for i in range(3):
            rec = create_scan_record("a", f"h{i}", f"1.1.1.{i}", "t", "tk")
            update_scan_status(rec.scan_id, "Done")
        assert len(get_scans_pending_push()) == 3