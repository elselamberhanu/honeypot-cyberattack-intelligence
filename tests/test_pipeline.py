"""Tests for the pipeline that connects the project modules."""

from src import analysis, collector, storage
from src.pipeline import run_pipeline


def test_pipeline_calls_modules_in_order(monkeypatch, tmp_path):
    """Check that the pipeline passes data through each stage correctly."""

    # Use a temporary path so the test cannot modify the real project database.
    db_path = tmp_path / "test_honeypot.db"
    log_path = tmp_path / "sample_cowrie_raw.jsonl"

    sample_events = [
        {
            "timestamp": "2026-10-16T08:41:38Z",
            "eventid": "cowrie.session.connect",
            "src_ip": "192.0.2.10",
            "session": "sample-session-001",
            "protocol": "ssh",
            "username": None,
            "input": None,
            "message": "Connection received",
            "extra": {},
        }
    ]

    expected_results = {
        "summary": {
            "total_events": 1,
            "unique_source_ips": 1,
            "successful_logins": 0,
            "failed_logins": 0,
            "command_events": 0,
            "unique_sessions": 1,
        },
        "alerts": [],
    }

    # Record each function call so we can check the workflow order.
    calls = []

    def fake_init_db(db_path):
        calls.append(("init_db", db_path))

    def fake_read_events(received_log_path):
        calls.append(("read_events", received_log_path))
        return sample_events

    def fake_insert_events(events, db_path):
        calls.append(("insert_events", events, db_path))
        return len(events)

    def fake_get_events(db_path):
        calls.append(("get_events", db_path))
        return sample_events

    def fake_analyze_events(events):
        calls.append(("analyze_events", events))
        return expected_results

    # Replace the real functions with controlled test versions.
    # raising=False allows the tests to work while modules are being built.
    monkeypatch.setattr(storage, "init_db", fake_init_db, raising=False)
    monkeypatch.setattr(collector, "read_events", fake_read_events, raising=False)
    monkeypatch.setattr(
        storage, "insert_events", fake_insert_events, raising=False
    )
    monkeypatch.setattr(storage, "get_events", fake_get_events, raising=False)
    monkeypatch.setattr(
        analysis, "analyze_events", fake_analyze_events, raising=False
    )

    # Run the pipeline.
    result = run_pipeline(log_path, db_path=db_path)

    # Verify the returned result.
    assert result == expected_results

    # Verify every stage ran in the expected order.
    assert [call[0] for call in calls] == [
        "init_db",
        "read_events",
        "insert_events",
        "get_events",
        "analyze_events",
    ]

    # Verify the pipeline passed the correct paths and event data.
    assert calls[0] == ("init_db", db_path)
    assert calls[1] == ("read_events", log_path)
    assert calls[2] == ("insert_events", sample_events, db_path)
    assert calls[3] == ("get_events", db_path)
    assert calls[4] == ("analyze_events", sample_events)


def test_pipeline_rejects_invalid_analysis_result(monkeypatch, tmp_path):
    """Check that a missing summary or alerts key raises a clear error."""

    db_path = tmp_path / "test_honeypot.db"

    # These replacements let us test pipeline validation without a real database.
    monkeypatch.setattr(storage, "init_db", lambda db_path: None, raising=False)
    monkeypatch.setattr(collector, "read_events", lambda path: [], raising=False)
    monkeypatch.setattr(
        storage, "insert_events", lambda events, db_path: 0, raising=False
    )
    monkeypatch.setattr(storage, "get_events", lambda db_path: [], raising=False)
    monkeypatch.setattr(
        analysis, "analyze_events", lambda events: {"alerts": []}, raising=False
    )

    import pytest

    with pytest.raises(ValueError, match="summary"):
        run_pipeline("unused.jsonl", db_path=db_path)