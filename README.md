# Honeypot-Based Cyberattack Intelligence Platform

## Project overview

The **Honeypot-Based Cyberattack Intelligence Platform** is a Python-based security monitoring and analysis system that uses [Cowrie](https://github.com/cowrie/cowrie), a deliberately deployed SSH/Telnet honeypot, to collect and analyze activity directed at a controlled environment.

The platform processes Cowrie logs, standardizes security events, stores them in an SQLite database, identifies selected suspicious activity patterns, and presents useful security insights through a Streamlit dashboard.

The project aims to demonstrate how honeypot data can be transformed into structured, understandable information that supports the investigation of potential cyberattacks.

## How it works
The platform follows this processing workflow:

**Cowrie JSONL log → collector and normalization → SQLite storage → analysis and alerts → Streamlit dashboard**

## Main Features

- **Event Collection:** Cowrie records interactions with the honeypot in JSON Lines (JSONL) log files.
- **Log Transfer:** A shared folder transfers Cowrie log files from the honeypot environment to the project environment.
- **Event Normalization:** Converts usable log records into a standardized nine-field event structure.
- **Persistent Storage:** Stores normalized events in SQLite and prevents duplicate event insertion.
- **Security Event Analysis:** Calculates activity summaries and identifies selected suspicious patterns.
- **Alert Generation:** Produces rule-based alerts to highlight activity that may warrant further investigation.
- **Interactive Dashboard:** Uses Streamlit to display stored events, summary metrics, and security alerts.
- **Automated Testing:** Includes tests for collection, storage, analysis, and pipeline behavior.
- **Modular Architecture:** Separates collection, storage, analysis, pipeline orchestration, and dashboard responsibilities.

## Main components

- `src/collector.py` — reads Cowrie JSON Lines and normalizes usable events.
- `src/storage.py` — validates and stores events in `data/honeypot.db`, preventing duplicate inserts.
- `src/analysis.py` — calculates event summaries and flags selected patterns for investigation.
- `src/pipeline.py` — coordinates collection, storage, and analysis.
- `dashboard_streamlit.py` — serves as the Streamlit dashboard entry point.
- `dashboard\` — contains dashboard components for displaying stored events, summary metrics, and alerts.
- `tests/` — automated tests and sanitized fixtures.

## Repository layout

```text
honeypot-cyberattack-intelligence/
├── dashboard/
│   ├── alerts.py
│   ├── charts.py
│   ├── components.py
│   ├── event_explorer.py
│   ├── styles.py
│   └── __init__.py
├── data/
│   └── .gitkeep
├── docs/
│   ├── event-schema.md
│   ├── technical-contract.md
│   ├── setup-and-running.md
│   ├── testing-and-results.md
│   └── team-contributions.md
├── src/
│   ├── collector.py
│   ├── storage.py
│   ├── analysis.py
│   └── pipeline.py
├── tests/
│   ├── fixtures/
│   │   └── sample_events.jsonl
│   ├── test_collector.py
│   ├── test_storage.py
│   ├── test_analysis.py
│   └── test_pipeline.py
├── dashboard_streamlit.py
├── README.md
└── requirements.txt
```

## Technology Stack

- **Python** — core implementation and pipeline processing.
- **Cowrie** — SSH/Telnet honeypot used to collect interaction logs.
- **SQLite** — persistent storage for normalized events.
- **Streamlit** — interactive dashboard.
- **Pandas** — data handling and dashboard support.
- **Pytest** — automated testing.

## Development principles

- Use the isolated lab and dummy credentials for testing.
- Never commit raw Cowrie logs, passwords, private keys, or real secrets.
- Develop and test against anonymized sample data where possible.
- Keep findings explainable with documented rules; machine learning is not required.
- Treat all honeypot input as untrusted text. Never execute commands collected by Cowrie.
- Coordinate shared interfaces before integrating independently developed modules.

## Setup and Usage

Install the dependencies, configure access to your Cowrie JSONL logs, run the processing pipeline, and launch the Streamlit dashboard to explore collected events and security alerts. Run the automated tests to verify the main modules.

- Refer to [Setup and Running](docs/setup-and-running.md) for detailed instructions.

## Testing and Validation

- Refer to - [Testing and results](docs/testing-and-results.md).

## Team Members and Contributions

**Elselam Berhanu — CTC-5653-26:** Pipeline development, integration and project coordination.

**Firaol Tadesse — CTC-1192-26:** Updated dashboard development, frontend design, and local dashboard testing.

**Hawinet Teshome — CTC-977-26:** Event collection, normalization, and Cowrie testing.

**Kidus Elias — CTC-709-26:** Security event analysis and analysis testing.

**Yadeno Demissie — CTC-5884-26:** Dashboard component development, setup documentation, and testing results.

**Yohannes Belay — CTC-1445-26:** Data storage, SQLite database functionality, and database testing.

See [Team Members and Contributions](docs/team-contributions.md) for the full list of team members, CTC IDs, and their contributions.
## Documentation

- [Technical Contract](docs/technical-contract.md) — shared interfaces, database rules, detection behavior, and security requirements.
- [Event Schema](docs/event-schema.md) — the standardized nine-field event structure.
- [Setup and Running](docs/setup-and-running.md) — installation, configuration, and execution instructions.
- [Testing and Results](docs/testing-and-results.md) — test commands, recorded results, and validation limitations.
- [Team Members and Contributions](docs/team-contributions.md) — team member names, CTC IDs, and project responsibilities.

## Project Repository

[GitHub Repository](https://github.com/elselamberhanu/honeypot-cyberattack-intelligence)

## Project demo
- https://screenrec.com/share/9NQ5v8mcrS


