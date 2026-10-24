# Technical Contract — Honeypot-Based Cyberattack Intelligence Platform

**Purpose:** Keep the project modules compatible as team members develop and integrate them. Changes to shared interfaces must be agreed and reflected in the code, tests, and documentation.

This document defines the shared data format, Python functions, database design, analysis rules, testing requirements, security requirements, and integration workflow. All members must follow it.


## 1. Project architecture

The system follows this flow:

1. Cowrie records SSH honeypot activity in a raw JSON Lines log.
2. The collector reads the raw log and normalizes events.
3. The storage module inserts normalized events into SQLite.
4. The analysis module evaluates stored events and produces summary statistics and alerts.
5. The dashboard displays event data, statistics, and alerts.

The system must support testing with fixtures before connecting to live Cowrie.

## 2. Normalized event schema

Every event passed between the collector, storage, and analysis modules must use the field names defined in `docs/event-schema.md`.

Every normalized event must contain all nine keys. The first eight values must follow their declared types, and `extra` must be a dictionary.

## 3. Analysis output and initial rules

The summary contains `total_events`, `unique_source_ips`, `successful_logins`, `failed_logins`, `command_events`, and `unique_sessions`. Every alert contains `rule`, `severity`, `src_ip`, `session`, `timestamp`, and `description`.

- **Failed-login burst:** at least 5 `cowrie.login.failed` events from one non-null source IP in any rolling 5-minute window; high severity.
- **Successful simulated login:** a low-severity informational alert for each `cowrie.login.success` event.
- **Risky command patterns:** inspect `cowrie.command.input` text for patterns such as `whoami`, `uname`, `cat /etc/passwd`, `wget`, `curl`, `chmod`, and `rm -rf`. Basic reconnaissance is low severity; download or potentially destructive patterns are medium severity.
- **High command volume:** more than 20 command events for one non-null session in any rolling 5-minute window; medium severity.

These rules are indicators for investigation, not proof that an attack succeeded. Commands must be analyzed as text and never executed. Keep thresholds in named constants and test the time-window boundaries.

## 4. Security and data handling

- Never commit passwords, private keys, tokens, or captured credentials.
- Never commit the local SQLite database or unfiltered raw Cowrie logs.
- Use sanitized fixtures for tests.
- Treat commands and messages from a honeypot as untrusted input.
- Never execute collected commands.
- Use parameterized SQL.
- Validate data before inserting it into SQLite.
- Escape or sanitize untrusted content before rendering it in the dashboard.
- Use only the controlled lab for testing.
