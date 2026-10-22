"""A small Streamlit dashboard for the honeypot project.

Run from the repository root with: streamlit run dashboard_streamlit.py
This file reads events from src.storage; it does not collect or save events.
"""

from collections import Counter
from pathlib import Path
import os
import sys

import pandas as pd
import streamlit as st

# Add the project folder to Python's import path so src.storage can be found.
PROJECT_FOLDER = Path(__file__).resolve().parent
if str(PROJECT_FOLDER) not in sys.path:
    sys.path.insert(0, str(PROJECT_FOLDER))

from src.storage import DEFAULT_DB_PATH, get_events, init_db  # noqa: E402

# The dashboard can show basic metrics even if the analysis module is not ready.
try:
    from src.analysis import analyze_events
except ImportError:
    analyze_events = None

# Use HONEYPOT_DB_PATH if provided; otherwise use the normal project database.
configured_db = os.environ.get("HONEYPOT_DB_PATH")

if configured_db:
    DATABASE_FILE = Path(configured_db).resolve()
else:
    DATABASE_FILE = PROJECT_FOLDER / DEFAULT_DB_PATH

st.set_page_config(
    page_title="Honeypot Cyberattack Intelligence",
    layout="wide",
)

st.title("Honeypot Cyberattack Intelligence")
st.write("A simple view of events recorded by the Cowrie honeypot.")

# Sidebar controls stay simple: show the database location and refresh the page.
with st.sidebar:
    st.header("Controls")
    st.caption(f"Database: {DATABASE_FILE}")
    if st.button("Refresh data"):
        st.rerun()

# Stop early with a clear message if the pipeline has not created the database.
if not DATABASE_FILE.exists():
    st.warning(
        "The database has not been created yet. Run the project pipeline first."
    )
    st.stop()

# Use the project's storage functions instead of writing separate SQL here.
try:
    init_db(db_path=DATABASE_FILE)
    events = get_events(limit=1000, db_path=DATABASE_FILE)
except Exception as error:
    st.error(f"Could not read the project database: {error}")
    st.stop()

if not events:
    st.info("The database is empty. Ingest some sanitized sample events first.")
    st.stop()

# Calculate simple metrics from the normalized events.
event_types = [event.get("eventid") for event in events]
source_ips = {event.get("src_ip") for event in events if event.get("src_ip")}
sessions = {event.get("session") for event in events if event.get("session")}
failed_logins = event_types.count("cowrie.login.failed")
successful_logins = event_types.count("cowrie.login.success")
command_events = event_types.count("cowrie.command.input")
total_events = len(events)

# If analysis.py is ready, use its shared summary and alerts.
alerts = []
if callable(analyze_events):
    try:
        analysis_result = analyze_events(events)
        summary = analysis_result["summary"]
        alerts = analysis_result["alerts"]

        # Prefer the official counts from the analysis module.
        total_events = summary["total_events"]
        source_count = summary["unique_source_ips"]
        session_count = summary["unique_sessions"]
        failed_logins = summary["failed_logins"]
        successful_logins = summary["successful_logins"]
        command_events = summary["command_events"]
    except (KeyError, TypeError, ValueError) as error:
        source_count = len(source_ips)
        session_count = len(sessions)
        st.warning(f"Analysis results were not in the expected format: {error}")
else:
    source_count = len(source_ips)
    session_count = len(sessions)
    st.info("Analysis alerts will appear when src.analysis.analyze_events is available.")

st.header("Overview")
first_row = st.columns(3)
first_row[0].metric("Total events", total_events)
first_row[1].metric("Unique source IPs", source_count)
first_row[2].metric("Unique sessions", session_count)

second_row = st.columns(3)
second_row[0].metric("Failed logins", failed_logins)
second_row[1].metric("Successful logins", successful_logins)
second_row[2].metric("Command events", command_events)

st.divider()

# Count each event type so the team can quickly see what the honeypot recorded.
st.header("Events by type")
counts = Counter(str(event.get("eventid") or "unknown") for event in events)
event_table = pd.DataFrame([
    {"Event type": event_type, "Count": count}
    for event_type, count in counts.most_common()
])
st.dataframe(event_table, width="stretch", hide_index=True)

# Group events by the date portion of their normalized UTC timestamp.
st.header("Daily activity")
daily_counts = Counter()
for event in events:
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str) and len(timestamp) >= 10:
        daily_counts[timestamp[:10]] += 1

if daily_counts:
    chart_data = pd.DataFrame([
        {"Date (UTC)": day, "Events": count}
        for day, count in sorted(daily_counts.items())
    ]).set_index("Date (UTC)")
    st.line_chart(chart_data)
else:
    st.caption("No usable timestamps were found for the chart.")

st.divider()

# Display the alerts created by src.analysis; do not create detection rules here.
st.header("Analysis alerts")
if alerts:
    alert_table = pd.DataFrame([
        {
            "Severity": alert.get("severity"),
            "Rule": alert.get("rule"),
            "Source IP": alert.get("src_ip"),
            "Session": alert.get("session"),
            "Timestamp": alert.get("timestamp"),
            "Description": alert.get("description"),
        }
        for alert in alerts
    ])
    st.dataframe(alert_table, width="stretch", hide_index=True)
else:
    st.caption("No alerts are available for the events currently loaded.")

st.divider()

# Storage returns oldest-first, so reverse the list to show the newest events first.
st.header("Recent events")
recent_events = list(reversed(events))[:100]
recent_table = pd.DataFrame([
    {
        "Timestamp": event.get("timestamp"),
        "Event type": event.get("eventid"),
        "Source IP": event.get("src_ip"),
        "Username": event.get("username"),
        "Command/input": event.get("input"),
        "Session": event.get("session"),
        "Message": event.get("message"),
    }
    for event in recent_events
])
st.dataframe(recent_table, width="stretch", hide_index=True)

