# Technical Contract — Honeypot-Based Cyberattack Intelligence Platform

**Status:** Initial team specification  
**Purpose:** Allow all developers to build their modules independently and integrate them without changing interfaces unexpectedly.

This document defines the shared data format, Python functions, database design, analysis rules, testing requirements, security requirements, and integration workflow. All developers must follow it.

If an implementation detail conflicts with this document, follow this contract. If a technical blocker makes that impossible, document the problem and propose the smallest compatible change before merging.

---

## 1. Project architecture

The system follows this flow:

1. Cowrie records SSH honeypot activity in a raw JSON Lines log.
2. The collector reads the raw log and normalizes events.
3. The storage module inserts normalized events into SQLite.
4. The analysis module evaluates stored events and produces summary statistics and alerts.
5. The existing dashboard displays event data, statistics, and alerts.

The system must support testing with fixtures before connecting to live Cowrie.

### Technology choices

- Python 3 for application code and automated tests.
- JSON Lines for raw and normalized event files.
- SQLite for local event storage.
- Python's built-in `sqlite3` and `json` modules where suitable.
- `pytest` for automated tests.
- The existing dashboard framework must be preserved. Do not rebuild the dashboard.

---

## 2. Project structure

Use this structure for new code:

```text
honeypot-cyberattack-intelligence/
├── README.md
├── .gitignore
├── docs/
│   ├── event-schema.md
│   ├── technical-contract.md
│   └── test-results.md
├── src/
│   ├── __init__.py
│   ├── collector.py
│   ├── storage.py
│   ├── analysis.py
│   └── pipeline.py
├── tests/
│   ├── fixtures/
│   │   ├── sample_events.jsonl
│   │   └── sample_cowrie_raw.jsonl
│   ├── test_collector.py
│   ├── test_storage.py
│   ├── test_analysis.py
│   └── test_pipeline.py
├── app.py                 # Only if this matches the existing dashboard
└── requirements.txt
```

Do not move or overwrite the existing dashboard files just to match this example. Adapt the structure around the dashboard that already exists.

---

## 3. Normalized event schema

Every event passed between the collector, storage, and analysis modules must use the field names defined in `docs/event-schema.md`.

| Field | Type | Required key? | Value when unavailable |
|---|---|---|---|
| `timestamp` | String | Yes | Reject or skip records without a usable timestamp |
| `eventid` | String | Yes | Reject or skip records without an event ID |
| `src_ip` | String or null | Yes | `null` |
| `session` | String or null | Yes | `null` |
| `protocol` | String or null | Yes | `null` |
| `username` | String or null | Yes | `null` |
| `input` | String or null | Yes | `null` |
| `message` | String or null | Yes | `null` |
| `extra` | Dictionary/object | Yes | `{}` |

Every normalized event must contain all nine keys. The first eight values must follow their declared types, and `extra` must be a dictionary.

### Example

```python
{
    "timestamp": "2026-10-16T08:41:38Z",
    "eventid": "cowrie.command.input",
    "src_ip": "192.0.2.10",
    "session": "sample-session-001",
    "protocol": "ssh",
    "username": "sample_user",
    "input": "whoami",
    "message": "CMD: whoami",
    "extra": {}
}
```

The example is illustrative test data, not a real attacker record.

### Timestamp convention

Use UTC ISO 8601 strings. Prefer the `Z` suffix for UTC, such as `2026-10-16T08:41:38Z`.

### Raw versus normalized records

Raw Cowrie records are not required to contain these exact nine fields. The collector maps Cowrie's fields into the normalized schema.

Only normalized events should be passed to the storage and analysis interfaces.

Do not rename schema fields independently. If the schema must change, update the documentation and all dependent tests in the same coordinated change.

---

## 4. Person 2 — Collector interface

**File:** `src/collector.py`

### Function

```python
read_events(log_path)
```

### Input

- `log_path`: string or `pathlib.Path` pointing to a Cowrie JSON Lines log or sanitized raw fixture.

### Output

Return a list of normalized event dictionaries:

```python
[
    {
        "timestamp": "...",
        "eventid": "...",
        "src_ip": "...",
        "session": "...",
        "protocol": "ssh",
        "username": None,
        "input": None,
        "message": "...",
        "extra": {}
    }
]
```

The example uses abbreviated values for readability; actual returned events must contain valid values and all nine keys.

### Requirements

1. Read one JSON object per non-empty line.
2. Parse each line independently.
3. Normalize Cowrie fields into the agreed schema.
4. Preserve relevant non-sensitive additional fields inside `extra`.
5. Skip malformed or unusable records without crashing the whole file-processing operation.
6. Log a useful warning or count for skipped records.
7. Never print or persist captured passwords or secrets in normalized events.
8. Do not invent missing source IPs, usernames, timestamps, or session IDs.
9. Do not deduplicate events in the collector. Leave duplicate-ingestion protection to storage.

The collector should not connect to SQLite or implement detection rules.

---

## 5. Person 3 — SQLite storage interface

**File:** `src/storage.py`

### Database location

Use:

```text
data/honeypot.db
```

This is a local development database. The database file must not be committed to GitHub.

The module must allow tests to supply a temporary database path, so tests do not modify a developer's real database.

### Table

Create a table named `events` with the following columns:

| Column | SQLite type | Rule |
|---|---|---|
| `id` | INTEGER | Primary key, auto-incrementing |
| `event_hash` | TEXT | Unique event fingerprint |
| `timestamp` | TEXT | Required |
| `eventid` | TEXT | Required |
| `src_ip` | TEXT | Nullable |
| `session` | TEXT | Nullable |
| `protocol` | TEXT | Nullable |
| `username` | TEXT | Nullable |
| `input` | TEXT | Nullable |
| `message` | TEXT | Nullable |
| `extra` | TEXT | JSON-encoded object |

`id` and `event_hash` are database implementation fields, not part of the nine-field normalized event contract.

### Required functions

```python
init_db(db_path="data/honeypot.db")
insert_events(events, db_path="data/honeypot.db")
get_events(limit=1000, db_path="data/honeypot.db")
```

### `init_db(db_path)`

- Create the parent directory if necessary.
- Create the database table if it does not exist.
- Be safe to call more than once.

### `insert_events(events, db_path)`

- Accept a list of normalized event dictionaries.
- Validate the required schema.
- Use parameterized SQL queries.
- Encode `extra` as JSON before storing it.
- Calculate a stable SHA-256 fingerprint from the canonical normalized event representation.
- Use the fingerprint to avoid inserting the same event repeatedly.
- Commit successful inserts and handle database errors clearly.
- Return the number of newly inserted events as an integer.

The fingerprint must be calculated consistently from the normalized event content, including the timestamp, event ID, source, session, and other normalized fields. Do not use a random value or database row ID for deduplication.

### `get_events(limit=1000, db_path=...)`

- Return a list of dictionaries.
- Each dictionary must contain the nine normalized field names.
- Decode `extra` back into a Python dictionary.
- Exclude `id` and `event_hash` from the public normalized result.
- Return at most `limit` events, ordered by timestamp ascending.
- Use a sensible positive default limit and reject invalid limits.

### Additional requirements

- Initialize the database before inserting or retrieving records.
- Do not use a shared global SQLite connection that remains open indefinitely.
- Close database connections after each operation.
- Allow a custom database path in every function for testing.
- Keep database creation and SQL statements inside `storage.py`.

---

## 6. Person 4 — Analysis interface

**File:** `src/analysis.py`

### Function

```python
analyze_events(events)
```

### Input

A list of normalized event dictionaries, usually returned by `get_events()`.

### Output

Always return a dictionary with these top-level keys:

```python
{
    "summary": {},
    "alerts": []
}
```

The `summary` dictionary must contain:

- `total_events`: number of input events
- `unique_source_ips`: number of distinct non-null source IPs
- `successful_logins`: number of successful login events
- `failed_logins`: number of failed login events
- `command_events`: number of command-input events
- `unique_sessions`: number of distinct non-null session IDs

The `alerts` value must be a list of alert dictionaries with these fields:

```python
{
    "rule": "failed_login_burst",
    "severity": "medium",
    "src_ip": "192.0.2.10",
    "session": None,
    "timestamp": "2026-10-16T08:41:38Z",
    "description": "Five or more failed login events from one source within five minutes."
}
```

This is an example of the output format, not a claim that this alert exists in the current fixture.

Every alert must include `rule`, `severity`, `src_ip`, `session`, `timestamp`, and `description`. If a value is unavailable, use `None` where appropriate. Do not invent values.

### Detection rules

Implement these rules first. Keep thresholds in named constants so they are easy to explain and adjust.

#### Rule A — Repeated failed logins

- Recognize `cowrie.login.failed`.
- Trigger when one non-null source IP produces **at least 5 failed login events within any rolling 5-minute window**.
- Severity: `high`.
- Required fields: `timestamp`, `eventid`, `src_ip`.
- Group by source IP.

#### Rule B — Successful simulated logins

- Recognize `cowrie.login.success`.
- Count successful simulated login events in the summary.
- Generate a low-severity informational alert for each successful simulated login.
- Required fields: `eventid`, `timestamp`, `src_ip`, `username`, `session`.

A Cowrie simulated login is not proof that the source compromised a real system.

#### Rule C — Potentially risky commands

- Recognize `cowrie.command.input`.
- Compare the command input against a small documented list of patterns associated with reconnaissance or potentially harmful activity.
- Start with patterns such as `whoami`, `uname`, `cat /etc/passwd`, `wget`, `curl`, `chmod`, and `rm -rf`.
- Severity: `low` for basic reconnaissance patterns; `medium` for patterns suggesting downloads or destructive actions.
- Required fields: `eventid`, `input`, `src_ip`, `timestamp`.
- Do not execute commands. Analyze them as text only.

These patterns are indicators for investigation, not proof of malicious intent. Ordinary administrative commands can appear in legitimate sessions.

#### Rule D — High command volume

- Recognize `cowrie.command.input`.
- Trigger when one non-null session has **more than 20 command events within any rolling 5-minute window**.
- Severity: `medium`.
- Required fields: `timestamp`, `eventid`, `session`, `src_ip`.

### Analysis requirements

1. Handle an empty event list without crashing.
2. Do not modify the input event dictionaries.
3. Handle missing optional values safely.
4. Parse timestamps consistently as UTC.
5. Sort events by timestamp for window-based rules.
6. Avoid generating multiple identical alerts for the same rule and same time window.
7. Document every rule, its threshold, and its limitations.
8. Do not describe an alert as proof that an attack succeeded.

---

## 7. Person 1 — Pipeline interface

**File:** `src/pipeline.py`

### Function

```python
run_pipeline(log_path)
```

### Required behavior

1. Initialize SQLite using `init_db()`.
2. Read and normalize the log with `read_events(log_path)`.
3. Insert the normalized events using `insert_events(events)`.
4. Retrieve stored events using `get_events()`.
5. Analyze the retrieved events using `analyze_events(events)`.
6. Return the analysis result dictionary.

The returned dictionary must follow the analysis output contract:

```python
{
    "summary": {...},
    "alerts": [...]
}
```

The pipeline must not duplicate the collector's parsing logic, create its own database schema, or implement its own detection rules.

The pipeline may accept an optional database path if needed for testing, but keep the agreed `run_pipeline(log_path)` call working with the default configuration.

Repeated pipeline runs must not repeatedly insert the same events. The analysis should use the stored event collection, subject to the retrieval limit.

---

## 8. Person 5 — Testing and documentation

**Main files:** `tests/` and `docs/`

Use `pytest` for automated tests.

### Required tests

#### Collector

- Parses a valid raw Cowrie record.
- Maps fields into all nine normalized fields.
- Handles optional or missing values safely.
- Skips malformed JSON lines.
- Does not expose captured passwords in normalized output.

#### Storage

- Initializes a new database.
- Inserts and retrieves normalized events.
- Preserves the nine field names.
- Converts `extra` between a Python dictionary and SQLite JSON text.
- Avoids duplicate insertion of the same normalized event.
- Supports a temporary database path.

#### Analysis

- Handles an empty list.
- Counts successful logins, failed logins, commands, unique sources, and unique sessions.
- Triggers the failed-login rule at the defined threshold.
- Does not trigger that rule below the threshold.
- Tests events at the edge of the five-minute window.
- Triggers the command-volume rule above 20 commands.
- Tests each risky-command category.
- Returns alerts with the required fields.

#### Pipeline

- Processes the sanitized fixture end to end.
- Returns the agreed analysis structure.
- Can run twice without duplicating the same fixture events in storage.

### Documentation deliverables

Create or update:

- `docs/test-results.md`: test cases, expected results, actual results, pass/fail status, and known limitations.
- `README.md`: installation, setup, how to run tests, how to run the pipeline, and how to launch the existing dashboard.
- Final report draft: project objective, architecture, implementation, testing, results, limitations, and future improvements.

Do not claim a test passed unless it was actually run.

---

## 9. Dashboard integration contract

The existing dashboard must not be rebuilt as part of this task.

The dashboard owner and integration coordinator should inspect the current dashboard before changing its data source.

### Required dashboard data

The dashboard should be able to display, where supported by its current design:

- Total events.
- Successful and failed login counts.
- Unique source IPs.
- Command activity.
- Session activity.
- Recent events.
- Analysis alerts, including severity and description.

### Data source

Use the existing framework and preserve the dashboard's current layout where practical.

The preferred data source is the shared SQLite database and the analysis output. Avoid creating a second unrelated database or a different set of event field names.

If the dashboard runs in the same Python project, it may import `storage.py` and `analysis.py` directly. If the current dashboard is a separate application or uses a remote connection, the integration coordinator must adapt the connection safely after inspecting its implementation.

Do not hard-code obsolete VM addresses or embed SSH passwords in source code. Never expose the management SSH service to the public internet for this project.

---

## 10. Testing fixtures and live Cowrie

The existing `tests/fixtures/sample_events.jsonl` contains normalized example events. Use it for storage and analysis tests.

The collector needs a separate `tests/fixtures/sample_cowrie_raw.jsonl` containing sanitized records that resemble actual Cowrie raw log entries. Person 2 should prepare it from the observed Cowrie event structure, removing passwords and other sensitive values.

The actual Cowrie JSON log on Ubuntu is located at:

```text
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

Use it only in the controlled lab. Do not commit the raw log.

Every developer can start using the normalized fixture without installing Cowrie. Only the collector and integration work require access to realistic raw records or the live log.

---

## 11. Security and data handling

- Never commit passwords, private keys, tokens, or captured credentials.
- Never commit the local SQLite database or unfiltered raw Cowrie logs.
- Use sanitized fixtures for tests.
- Treat commands and messages from a honeypot as untrusted input.
- Never execute collected commands.
- Use parameterized SQL.
- Validate data before inserting it into SQLite.
- Escape or sanitize untrusted content before rendering it in the dashboard.
- Use only the controlled lab for testing.

---

## 12. Git and teamwork rules

Every developer must:

1. Pull the latest `main` before starting a new task.
2. Create a dedicated feature branch.
3. Make changes only for their assigned module and tests.
4. Run their tests before committing.
5. Review staged files before committing.
6. Push their own branch and open a pull request into `main`.
7. Describe what changed and how it was tested.
8. Wait for the integration coordinator to review and merge.

Suggested branches:

- `feature/pipeline`
- `feature/collector`
- `feature/storage`
- `feature/analysis`
- `feature/tests-docs`

Do not commit directly to `main`. Do not force-push shared branches. Keep the existing dashboard files intact unless a planned integration change requires editing them.

---

## 13. Definition of done

A module is ready to merge when:

- Its agreed function exists and accepts the documented arguments.
- It returns the documented output format.
- It uses the shared field names.
- Its tests pass.
- It does not contain secrets or raw logs.
- Its README or relevant documentation is updated.
- It has been reviewed by the integration coordinator.

The project is complete when the controlled Cowrie lab produces events that can be collected, normalized, stored in SQLite, analyzed, and displayed in the existing dashboard; the test suite passes; and the team can explain the results and limitations.
