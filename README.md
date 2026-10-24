# Honeypot-Based Cyberattack Intelligence Platform

## Project overview

This project uses Cowrie, a deliberately deployed SSH honeypot, to collect and analyze activity directed at a controlled environment. The platform organizes observed events and presents useful security insights in a Python dashboard.

## How it works

Cowrie JSONL log → collector and normalization → SQLite storage → analysis and alerts → Streamlit dashboard

## Main components

- `src/collector.py` — reads Cowrie JSON Lines and normalizes usable events.
- `src/storage.py` — validates and stores events in `data/honeypot.db`, preventing duplicate inserts.
- `src/analysis.py` — calculates event summaries and flags selected patterns for investigation.
- `src/pipeline.py` — coordinates collection, storage, and analysis.
- `dashboard\` — displays stored events, summary metrics, and alerts.
- `tests/` — automated tests and sanitized fixtures.

## Repository layout

- `docs/event-schema.md` — shared event format.
- `tests/fixtures/sample_events.jsonl` — anonymized normalized sample events.
- `src/` — planned collector, storage, analysis, and pipeline modules.
- `tests/` — test_collector.py, test_storage.py, test_analysis.py, test_pipeline.py
- dashboard_streamlit.py

## Development principles

- Use the isolated lab and dummy credentials for testing.
- Never commit raw Cowrie logs, passwords, private keys, or real secrets.
- Develop and test against anonymized sample data where possible.
- Keep findings explainable with documented rules; machine learning is not required.
- Treat all honeypot input as untrusted text. Never execute commands collected by Cowrie.
- Coordinate shared interfaces before integrating independently developed modules.

## Documentation

- [Technical contract](docs/technical-contract.md) — shared interfaces, database rules, detection behavior, and security requirements.
- [Event schema](docs/event-schema.md) — the nine normalized event fields.
- [Testing and results](docs/testing-and-results.md) — test commands, recorded results, and validation limits.


