"""SQLite storage for normalized honeypot events.

Agreed interface:
    init_db(db_path="data/honeypot.db")
    insert_events(events, db_path="data/honeypot.db") -> int (newly inserted)
    get_events(limit=1000, db_path="data/honeypot.db") -> list[dict]

Every stored/returned event has exactly the nine normalized fields:
timestamp, eventid, src_ip, session, protocol, username, input, message, extra.
`extra` is stored as JSON text and decoded back to a dict on retrieval.
"""

import hashlib
import json
import os
import sqlite3
from contextlib import closing

DEFAULT_DB_PATH = "data/honeypot.db"

# The nine normalized fields, in the agreed order. Used both to build the
# dictionaries we return and to make sure we never return extra keys.
EVENT_FIELDS = (
    "timestamp",
    "eventid",
    "src_ip",
    "session",
    "protocol",
    "username",
    "input",
    "message",
    "extra",
)

# Per the technical contract: timestamp and eventid must be non-empty strings
# (records without them are unusable); the other six scalar fields may be a
# string or null.
_REQUIRED_TEXT_FIELDS = ("timestamp", "eventid")
_OPTIONAL_TEXT_FIELDS = ("src_ip", "session", "protocol", "username", "input", "message")


class StorageError(Exception):
    """Raised when a database operation fails (wraps sqlite3.Error)."""


# "IF NOT EXISTS" makes this safe to run every time (init_db is idempotent).
# `event_hash` is UNIQUE: this is what stops the same event being stored twice.
# `extra` is TEXT because SQLite has no dict type; we keep JSON in it.
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash  TEXT NOT NULL UNIQUE,
    timestamp   TEXT NOT NULL,
    eventid     TEXT NOT NULL,
    src_ip      TEXT,
    session     TEXT,
    protocol    TEXT,
    username    TEXT,
    input       TEXT,
    message     TEXT,
    extra       TEXT NOT NULL DEFAULT '{}'
)
"""

# "INSERT OR IGNORE" silently skips a row if it would break the UNIQUE
# constraint on event_hash (i.e. it is a duplicate) instead of raising an
# error. The "?" placeholders are parameterized SQL: values are passed
# separately from the query text, so text like "'; DROP TABLE events; --"
# is stored as plain data and can never be executed (prevents SQL injection).
_INSERT_SQL = """
INSERT OR IGNORE INTO events
    (event_hash, timestamp, eventid, src_ip, session, protocol,
     username, input, message, extra)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

# Oldest first. If two events share a timestamp, `id` (insertion order) breaks
# the tie so the result order is always predictable. The column order here
# must match EVENT_FIELDS, because get_events() zips the two together.
_SELECT_SQL = """
SELECT timestamp, eventid, src_ip, session, protocol,
       username, input, message, extra
FROM events
ORDER BY timestamp ASC, id ASC
LIMIT ?
"""


def _connect(db_path):
    """Open a connection, creating the parent directory if needed."""
    # os.fspath lets db_path be either a str or a pathlib.Path.
    directory = os.path.dirname(os.fspath(db_path))
    # An empty directory means a bare filename like "test.db" (current folder),
    # and os.makedirs("") would raise an error, so only create when non-empty.
    if directory:
        os.makedirs(directory, exist_ok=True)
    return sqlite3.connect(db_path)


def _ensure_schema(conn):
    conn.execute(_CREATE_TABLE_SQL)


def _canonical(event):
    """Return the nine normalized fields as a plain dict (missing -> None/{})."""
    if not isinstance(event, dict):
        raise ValueError("each event must be a dictionary")
    # Schema validation. Error messages name the FIELD only, never its value,
    # so a captured credential can never leak into an error message.
    for name in _REQUIRED_TEXT_FIELDS:
        value = event.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"event '{name}' is required and must be a non-empty string")
    for name in _OPTIONAL_TEXT_FIELDS:
        value = event.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"event '{name}' must be a string or null")
    # Build a fresh dict containing only the eight scalar fields. Anything
    # else in the incoming event (unknown keys) is dropped, and missing keys
    # become None so every stored row has the same shape.
    clean = {name: event.get(name) for name in EVENT_FIELDS if name != "extra"}
    # `extra` gets special handling: it must be a dict (the schema says so),
    # and a missing/None value is treated as an empty dict.
    extra = event.get("extra")
    if extra is None:
        extra = {}
    if not isinstance(extra, dict):
        raise ValueError("event 'extra' must be a dictionary")
    clean["extra"] = extra
    return clean


def _event_hash(clean):
    """Stable SHA-256 over the canonical, key-sorted JSON of the nine fields."""
    # sort_keys=True is the important part: {"a": 1, "b": 2} and
    # {"b": 2, "a": 1} must produce the same text, otherwise two identical
    # events could get different hashes and slip past duplicate detection.
    # `default=str` stops json.dumps crashing on unusual values (e.g. a
    # datetime) by converting them to text instead.
    payload = json.dumps(clean, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the database file, its directory, and the `events` table."""
    # closing(...) guarantees conn.close() runs even if an error happens.
    # NOTE: sqlite3's own `with conn:` does NOT close the connection; it only
    # commits (or rolls back on error). That is why we need both `with`s:
    # the outer one closes, the inner one handles the transaction.
    try:
        with closing(_connect(db_path)) as conn:
            with conn:
                _ensure_schema(conn)
    except sqlite3.Error as exc:
        raise StorageError(f"could not initialize database: {exc}") from exc


def insert_events(events, db_path=DEFAULT_DB_PATH):
    """Insert normalized events; return how many were newly inserted.

    Duplicates (same event content) are skipped via the unique event_hash.
    The whole batch is validated first, so a bad event inserts nothing.
    """
    # Step 1: validate and prepare every row BEFORE touching the database.
    # If any event is invalid, _canonical raises here and nothing has been
    # written yet, so a batch is never half-inserted because of bad input.
    # `events or []` lets callers pass None without crashing.
    rows = []
    for event in events or []:
        clean = _canonical(event)
        rows.append(
            (
                _event_hash(clean),
                clean["timestamp"],
                clean["eventid"],
                clean["src_ip"],
                clean["session"],
                clean["protocol"],
                clean["username"],
                clean["input"],
                clean["message"],
                # Same sort_keys idea as the hash: consistent JSON text.
                json.dumps(clean["extra"], sort_keys=True, ensure_ascii=False, default=str),
            )
        )

    try:
        with closing(_connect(db_path)) as conn:
            with conn:  # one transaction: commit on success, rollback on error
                _ensure_schema(conn)
                # How we count only NEW rows: conn.total_changes is the running
                # number of rows this connection has changed. INSERT OR IGNORE
                # adds 0 for a skipped duplicate and 1 for a real insert, so the
                # difference before/after is exactly the number newly inserted.
                # (cursor.rowcount is less reliable with INSERT OR IGNORE.)
                before = conn.total_changes
                for row in rows:
                    conn.execute(_INSERT_SQL, row)
                return conn.total_changes - before
    except sqlite3.Error as exc:
        raise StorageError(f"could not insert events: {exc}") from exc


def get_events(limit=1000, db_path=DEFAULT_DB_PATH):
    """Return up to `limit` events, oldest first, as nine-field dictionaries."""
    # Reject invalid limits instead of guessing. bool is checked separately
    # because True/False are technically ints in Python. This also matters for
    # safety: SQLite treats a negative LIMIT as "no limit at all".
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")

    try:
        with closing(_connect(db_path)) as conn:
            # Make sure the table exists so asking a brand-new/missing database
            # returns an empty list instead of a "no such table" error.
            with conn:
                _ensure_schema(conn)
            cursor = conn.execute(_SELECT_SQL, (limit,))
            results = []
            for row in cursor.fetchall():
                # zip pairs each column value with its field name, turning the
                # row tuple into a dict like {"timestamp": ..., "eventid": ...}.
                event = dict(zip(EVENT_FIELDS, row))
                # Reverse of what insert_events did: JSON text -> real dict.
                # An empty/NULL value falls back to {} so `extra` is always a dict.
                event["extra"] = json.loads(event["extra"]) if event["extra"] else {}
                results.append(event)
            return results
    except sqlite3.Error as exc:
        raise StorageError(f"could not read events: {exc}") from exc
