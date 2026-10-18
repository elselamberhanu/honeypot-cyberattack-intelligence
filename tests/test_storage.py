import json
import sqlite3
from pathlib import Path

import pytest

from src.storage import EVENT_FIELDS, get_events, init_db, insert_events

# Path to the shared normalized sample fixture, built relative to this file so
# the tests work no matter which folder pytest is launched from.
FIXTURE = Path(__file__).parent / "fixtures" / "sample_events.jsonl"


def make_event(**overrides):
    """Build a valid normalized event; tests override only what they care about.

    Keeping one base event means each test shows just the field it is
    checking (e.g. make_event(src_ip=None)) instead of repeating nine keys.
    """
    event = {
        "timestamp": "2026-10-17T10:00:00Z",
        "eventid": "cowrie.login.failed",
        "src_ip": "203.0.113.10",  # documentation-range IP, not a real host
        "session": "abc123",
        "protocol": "ssh",
        "username": "root",
        "input": None,
        "message": "login attempt failed",
        "extra": {"sensor": "lab"},
    }
    event.update(overrides)
    return event


@pytest.fixture
def db(tmp_path):
    # tmp_path is a fresh temporary folder pytest creates for each test and
    # deletes afterwards, so tests never touch the real data/honeypot.db and
    # never leak data into each other.
    return str(tmp_path / "test.db")


def test_init_db_creates_file_and_events_table(db):
    init_db(db)
    # Open the database directly with sqlite3 (not through storage.py) so we
    # verify the real table exists, rather than trusting our own module.
    conn = sqlite3.connect(db)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
    finally:
        conn.close()
    assert "events" in tables


def test_init_db_creates_missing_directory(tmp_path):
    # The "nested/dir" folders do not exist yet; init_db must create them.
    path = tmp_path / "nested" / "dir" / "honeypot.db"
    init_db(str(path))
    assert path.exists()


def test_init_db_is_idempotent(db):
    # Calling init_db again must NOT wipe existing data (CREATE IF NOT EXISTS).
    init_db(db)
    insert_events([make_event()], db)
    init_db(db)
    assert len(get_events(db_path=db)) == 1


def test_get_events_on_empty_database_returns_empty_list(db):
    init_db(db)
    assert get_events(db_path=db) == []


def test_insert_and_retrieve_round_trip(db):
    event = make_event()
    assert insert_events([event], db) == 1
    # Exact equality: what comes out must be identical to what went in.
    assert get_events(db_path=db) == [event]


def test_returned_events_have_exactly_nine_fields(db):
    insert_events([make_event()], db)
    result = get_events(db_path=db)[0]
    # Comparing a tuple of keys checks both the names AND their order, so
    # extra or missing fields (like the internal id/event_hash) would fail.
    assert tuple(result.keys()) == EVENT_FIELDS


def test_extra_is_serialized_and_decoded_to_dict(db):
    # A nested structure proves JSON handles more than flat key/value pairs.
    extra = {"count": 3, "tags": ["a", "b"], "nested": {"k": "v"}}
    insert_events([make_event(extra=extra)], db)
    result = get_events(db_path=db)[0]
    # It is stored as JSON text, but must come back as a real dict, not a str.
    assert isinstance(result["extra"], dict)
    assert result["extra"] == extra


def test_missing_or_none_extra_becomes_empty_dict(db):
    event = make_event()
    del event["extra"]  # case 1: the key is absent entirely
    # case 2: the key is present but None; different session so it is not
    # treated as a duplicate of the first event.
    insert_events([event, make_event(session="s2", extra=None)], db)
    assert all(e["extra"] == {} for e in get_events(db_path=db))


def test_null_fields_are_preserved(db):
    # Optional fields may be null; they must come back as None, not "" or "None".
    event = make_event(src_ip=None, session=None, protocol=None,
                       username=None, input=None, message=None)
    insert_events([event], db)
    assert get_events(db_path=db) == [event]


def test_insert_events_skips_duplicates(db):
    event = make_event()
    assert insert_events([event], db) == 1
    # Second insert of the same event: nothing new, so the count is 0.
    assert insert_events([event], db) == 0
    assert len(get_events(db_path=db)) == 1


def test_duplicates_within_one_batch_are_skipped(db):
    event = make_event()
    # dict(event) is a separate copy with identical content, so this checks
    # that duplicates are detected by content, not by object identity.
    assert insert_events([event, dict(event)], db) == 1


def test_duplicate_detection_ignores_extra_key_order(db):
    # Same content, different key order inside `extra`. The hash uses
    # sort_keys=True, so these must count as the same event.
    a = make_event(extra={"x": 1, "y": 2})
    b = make_event(extra={"y": 2, "x": 1})
    assert insert_events([a, b], db) == 1


def test_different_events_are_both_stored(db):
    # Guards against the opposite bug: a hash that is too loose and wrongly
    # treats genuinely different events as duplicates.
    a = make_event(timestamp="2026-10-17T10:00:00Z")
    b = make_event(timestamp="2026-10-17T10:00:01Z")
    assert insert_events([a, b], db) == 2


def test_insert_empty_list_returns_zero(db):
    assert insert_events([], db) == 0


def test_custom_paths_are_isolated(tmp_path):
    # Two different database files must not share data.
    db1, db2 = str(tmp_path / "one.db"), str(tmp_path / "two.db")
    insert_events([make_event()], db1)
    assert len(get_events(db_path=db1)) == 1
    assert get_events(db_path=db2) == []


def test_events_returned_oldest_first(db):
    late = make_event(timestamp="2026-10-17T12:00:00Z", session="late")
    early = make_event(timestamp="2026-10-17T08:00:00Z", session="early")
    mid = make_event(timestamp="2026-10-17T10:00:00Z", session="mid")
    # Inserted deliberately out of order to prove sorting happens on read.
    insert_events([late, early, mid], db)
    assert [e["session"] for e in get_events(db_path=db)] == ["early", "mid", "late"]


def test_same_timestamp_keeps_insertion_order(db):
    # All five share one timestamp, so only the id tie-breaker decides order.
    # Each gets a unique session so they are not skipped as duplicates.
    events = [make_event(session=f"s{i}") for i in range(5)]
    insert_events(events, db)
    assert [e["session"] for e in get_events(db_path=db)] == [f"s{i}" for i in range(5)]


def test_limit_restricts_number_of_results(db):
    insert_events([make_event(session=f"s{i}") for i in range(10)], db)
    assert len(get_events(limit=3, db_path=db)) == 3


def test_default_limit_is_1000(db):
    # 1005 distinct events; with no limit argument only 1000 may come back.
    insert_events([make_event(session=f"s{i}") for i in range(1005)], db)
    assert len(get_events(db_path=db)) == 1000


def test_non_dict_extra_is_rejected_and_nothing_inserted(db):
    # The batch has one good event and one bad one. The bad one must raise
    # AND the good one must not be saved either (the batch is all-or-nothing).
    with pytest.raises(ValueError):
        insert_events([make_event(), make_event(session="x", extra="oops")], db)
    assert get_events(db_path=db) == []


def test_non_dict_event_is_rejected(db):
    with pytest.raises(ValueError):
        insert_events(["not a dict"], db)


def test_sql_injection_text_is_stored_literally(db):
    # If SQL were built by string concatenation this would drop the table.
    # With parameterized queries it is just stored and returned as text.
    nasty = "'; DROP TABLE events; --"
    insert_events([make_event(username=nasty, input=nasty)], db)
    result = get_events(db_path=db)
    assert result[0]["username"] == nasty
    assert result[0]["input"] == nasty


def test_unicode_round_trip(db):
    # Amharic text and an accented character must survive storing and reading
    # (ensure_ascii=False in the JSON, UTF-8 in SQLite).
    event = make_event(message="ሰላም — test", extra={"note": "ñ"})
    insert_events([event], db)
    assert get_events(db_path=db) == [event]


# Skipped automatically if the fixture file is not in the repo, so the test
# suite still passes on a checkout that does not have it.
@pytest.mark.skipif(not FIXTURE.exists(), reason="sample_events.jsonl not present")
def test_sample_fixture_round_trip(db):
    # JSON Lines: one JSON object per line; blank lines are ignored.
    with open(FIXTURE, encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh if line.strip()]
    inserted = insert_events(events, db)
    # +10 leaves headroom so the limit never cuts off the fixture events.
    stored = get_events(limit=len(events) + 10, db_path=db)
    # The fixture may itself contain duplicate lines, so compare against what
    # was actually stored rather than assuming one row per input line.
    assert inserted == len(stored)
    # Loading the same file again must add nothing.
    assert insert_events(events, db) == 0
    for e in stored:
        assert tuple(e.keys()) == EVENT_FIELDS
        assert isinstance(e["extra"], dict)
