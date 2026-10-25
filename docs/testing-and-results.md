# Testing and Results

## Run the tests

From the repository root, activate the project's Python environment if applicable, install the dependencies from `requirements.txt`, then run:

```bash
python -m pytest -v
```

Use sanitized fixtures for routine tests. Tests that write to SQLite should use temporary database paths rather than the developer's local `data/honeypot.db`.

## Required coverage

- **Collector:** valid Cowrie records, field mapping, optional fields, malformed lines, and secret filtering.
- **Storage:** database initialization, insert/retrieve round trip, `extra` JSON conversion, validation, duplicate prevention, custom paths, and invalid limits.
- **Analysis:** summary counts, empty input, alert fields, detection thresholds, five-minute window boundaries, and risky-command patterns.
- **Pipeline:** fixture processing, expected output shape, and repeated runs without duplicate inserts.
- **Integration:** confirm sanitized or controlled Cowrie records can pass through collection, storage, analysis, and the Streamlit dashboard.

## Recorded result

A previous local run reported:

```text
38 passed in 2.56s
```

This is a historical result, not a guarantee that the current checkout passes. 

## Known validation limit

Passing automated tests does not by itself prove that the system works with a live Cowrie log or that every alert represents malicious activity. Detection patterns are simple indicators and may produce false positives.
