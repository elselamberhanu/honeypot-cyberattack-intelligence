"""Coordinate the honeypot event collection, storage, and analysis steps."""


def run_pipeline(log_path, db_path="data/honeypot.db"):
    """
    Run the complete event-processing workflow.

    Args:
        log_path: Path to a Cowrie JSON Lines log or sanitized raw fixture.
        db_path: Path to the SQLite database used to store events.

    Returns:
        A dictionary containing "summary" and "alerts".
    """

    # Import the functions here so this module can be imported while
    # teammates are still implementing their modules.
    from .collector import read_events
    from .storage import init_db, insert_events, get_events
    from .analysis import analyze_events

    # Step 1: Make sure the database and its events table exist.
    init_db(db_path=db_path)

    # Step 2: Read raw Cowrie records and normalize them.
    new_events = read_events(log_path)

    # Step 3: Save normalized events. Storage handles duplicate prevention.
    insert_events(new_events, db_path=db_path)

    # Step 4: Retrieve the stored events for analysis.
    stored_events = get_events(db_path=db_path)

    # Step 5: Calculate summary statistics and detection alerts.
    results = analyze_events(stored_events)

    # Step 6: Check that analysis returned the agreed output structure.
    if not isinstance(results, dict):
        raise TypeError("analyze_events() must return a dictionary.")

    if "summary" not in results or "alerts" not in results:
        raise ValueError(
            'Analysis results must contain both "summary" and "alerts".'
        )

    return results