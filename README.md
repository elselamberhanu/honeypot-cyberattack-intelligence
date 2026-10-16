# Honeypot-Based Cyberattack Intelligence Platform

## Project overview

This project uses Cowrie, a deliberately deployed SSH/Telnet honeypot, to collect and analyze activity directed at a controlled environment. The platform organizes observed events and presents useful security insights in a Python dashboard.

## Planned architecture

1. **Cowrie:** captures activity in the isolated honeypot lab.
2. **Collector:** reads Cowrie JSON events and converts them into a common event format.
3. **SQLite storage:** saves normalized events for querying and reporting.
4. **Rule-based analysis:** calculates event counts and identifies activity using transparent rules.
5. **Dashboard:** presents summaries, sessions, login activity, commands, source IPs, and alerts.

The already built dashboard will be integrated with the collection and analysis components; it is not being rebuilt from scratch.

## Development status

The Cowrie honeypot has been tested in a controlled virtual-machine lab. The shared event schema and anonymized sample data are the starting point for software integration.

## Repository layout

- `docs/event-schema.md` — shared event format.
- `tests/fixtures/sample_events.jsonl` — anonymized normalized sample events.
- `src/` — planned collector, storage, analysis, and pipeline modules.
- `tests/` — automated tests.

## Development principles

- Use the isolated lab and dummy credentials for testing.
- Never commit raw Cowrie logs, passwords, private keys, or real secrets.
- Develop and test against anonymized sample data where possible.
- Keep findings explainable with documented rules; machine learning is not required.
- Coordinate shared interfaces before integrating independently developed modules.

## Team workflow

1. Each contributor works on a separate Git branch.
2. Commit and push work to that branch.
3. Open a pull request for review.
4. Merge into `main` after the changes have been reviewed and tested.

## Current limitation

The collector, database, analysis, and dashboard integration must be tested together before the platform can be considered complete.

