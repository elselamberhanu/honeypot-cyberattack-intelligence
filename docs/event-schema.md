# Normalized Event Schema

## Purpose

This document defines the shared event format used by the collector, database, analysis module, and dashboard.

## Format

- One JSON object per line in JSONL files.
- Timestamps use UTC in ISO 8601 format.
- Missing values use JSON `null`.
- The collector converts raw Cowrie events into this normalized format.
- Raw Cowrie logs and credentials must not be committed to GitHub.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | String | Event time in UTC, ISO 8601 |
| `eventid` | String | Cowrie event type, e.g. `cowrie.command.input` |
| `src_ip` | String or null | Source IP address |
| `session` | String or null | Session identifier |
| `protocol` | String or null | Protocol, e.g. `ssh` |
| `username` | String or null | Username associated with the event, if available |
| `input` | String or null | Input or command, if available |
| `message` | String or null | Human-readable event description |
| `extra` | Object | Approved additional fields |

## Example event

```json
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

The example IP address is reserved for documentation and is not a real attacker address.

## Team integration rules

1. The collector owns raw-log parsing and normalization.
2. The storage module saves normalized events to SQLite.
3. The analysis module calculates counts and transparent rule-based findings.
4. The dashboard displays data through the agreed storage and analysis interfaces.
5. Discuss schema changes with the team before changing required fields.
6. Do not store passwords in normalized events or publish raw Cowrie logs.
