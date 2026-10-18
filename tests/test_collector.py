
import json

from src.collector import (
    NORMALIZED_FIELDS,
    normalize_event,
    normalize_timestamp,
    read_events,
)


def test_normalizes_valid_event():
    raw = {
        "timestamp": "2026-10-16T10:00:00Z",
        "eventid": "cowrie.session.connect",
        "src_ip": "192.0.2.10",
        "session": "session-example-001",
        "protocol": "ssh",
        "src_port": 49100,
    }

    event = normalize_event(raw)

    assert event is not None
    assert set(event.keys()) == NORMALIZED_FIELDS
    assert event["src_ip"] == "192.0.2.10"
    assert event["username"] is None
    assert event["extra"]["src_port"] == 49100


def test_normalizes_timestamp_to_utc():
    result = normalize_timestamp("2026-10-16T13:00:00+03:00")

    assert result == "2026-10-16T10:00:00Z"


def test_rejects_invalid_timestamp():
    assert normalize_timestamp("not-a-timestamp") is None


def test_does_not_expose_password():
    raw = {
        "timestamp": "2026-10-16T10:00:00Z",
        "eventid": "cowrie.login.failed",
        "password": "FAKE_TEST_VALUE",
    }

    event = normalize_event(raw)

    assert event is not None
    assert "password" not in event
    assert "password" not in event["extra"]
    assert "FAKE_TEST_VALUE" not in json.dumps(event)
def test_filters_sensitive_fields():
    # Create an event containing several fields that may hold secrets.
    raw = {
        "timestamp": "2026-10-16T10:00:00Z",
        "eventid": "cowrie.login.failed",
        "api_key": "FAKE_API_KEY",
        "access_token": "FAKE_ACCESS_TOKEN",
        "credentials": "FAKE_CREDENTIALS",
        "private-key": "FAKE_PRIVATE_KEY",
    }

    # Convert the raw event into our normalized event.
    event = normalize_event(raw)

    # The event should still be accepted.
    assert event is not None

    # None of these sensitive fields should appear in extra data.
    assert "api_key" not in event["extra"]
    assert "access_token" not in event["extra"]
    assert "credentials" not in event["extra"]
    assert "private-key" not in event["extra"]

    # Check that the secret values are not present anywhere in the event.
    event_text = json.dumps(event)
    assert "FAKE_API_KEY" not in event_text
    assert "FAKE_ACCESS_TOKEN" not in event_text
    assert "FAKE_CREDENTIALS" not in event_text
    assert "FAKE_PRIVATE_KEY" not in event_text

def test_skips_malformed_json_line(tmp_path):
    log_path = tmp_path / "test_cowrie.jsonl"

    valid_record = {
        "timestamp": "2026-10-16T10:00:00Z",
        "eventid": "cowrie.session.connect",
        "src_ip": "192.0.2.10",
    }

    log_path.write_text(
        json.dumps(valid_record) + "\n{invalid json}\n",
        encoding="utf-8",
    )

    events = read_events(log_path)

    assert len(events) == 1
    assert events[0]["eventid"] == "cowrie.session.connect"
    assert set(events[0].keys()) == NORMALIZED_FIELDS


