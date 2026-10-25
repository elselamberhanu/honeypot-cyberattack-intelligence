"""Streamlit SOC dashboard for the Honeypot Cyberattack Intelligence platform.

Run from the repository root with:
    streamlit run dashboard_streamlit.py

This file is the main entry point that coordinates data retrieval, analysis,
and section rendering across dedicated dashboard modules.
"""

import os
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# Add the project root to sys.path so src and dashboard packages resolve reliably.
PROJECT_FOLDER = Path(__file__).resolve().parent
if str(PROJECT_FOLDER) not in sys.path:
    sys.path.insert(0, str(PROJECT_FOLDER))

from src.storage import DEFAULT_DB_PATH, get_events, init_db  # noqa: E402

try:
    from src.analysis import analyze_events, parse_timestamp
except ImportError:
    analyze_events = None
    parse_timestamp = None

from dashboard.styles import get_theme_css
from dashboard.components import (
    render_sidebar,
    render_header,
    render_kpi_cards,
    render_posture_banner,
)
from dashboard.charts import render_attack_activity_section
from dashboard.alerts import render_alerts_section
from dashboard.event_explorer import render_event_explorer


# ---------------------------------------------------------------------------
# Database Configuration
# ---------------------------------------------------------------------------
configured_db = os.environ.get("HONEYPOT_DB_PATH")

if configured_db:
    DATABASE_FILE = Path(configured_db).resolve()
else:
    DATABASE_FILE = PROJECT_FOLDER / DEFAULT_DB_PATH


# ---------------------------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Honeypot Cyberattack Intelligence",
    layout="wide",
    initial_sidebar_state="expanded",
)

event_limit = render_sidebar(DATABASE_FILE, default_limit=1000)
st.markdown(get_theme_css(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Database Ingestion & Validation
# ---------------------------------------------------------------------------
if not DATABASE_FILE.exists():
    st.markdown(
        """
        <div class="soc-header" style="border-left-color: var(--soc-alert-high-accent);">
            <h1 class="soc-title">Honeypot Cyberattack Intelligence</h1>
            <div class="soc-subtitle">SSH Threat Monitoring & Attack Behavior Analysis</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.warning(
        f"Database not found at `{DATABASE_FILE}`. "
        "Please run the project ingestion pipeline (src.pipeline) first to populate events."
    )
    st.stop()

try:
    init_db(db_path=DATABASE_FILE)
    events = get_events(limit=event_limit, db_path=DATABASE_FILE)
except Exception as error:
    st.error(f"Could not read the project database: {error}")
    st.stop()

if not events:
    st.markdown(
        """
        <div class="soc-header" style="border-left-color: var(--soc-alert-med-accent);">
            <h1 class="soc-title">Honeypot Cyberattack Intelligence</h1>
            <div class="soc-subtitle">SSH Threat Monitoring & Attack Behavior Analysis</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.info("The database is currently empty. Ingest normalized Cowrie sample events first.")
    st.stop()


# ---------------------------------------------------------------------------
# Metrics Calculation & Heuristic Analysis
# ---------------------------------------------------------------------------
event_types = [event.get("eventid") for event in events]
source_ips = {event.get("src_ip") for event in events if event.get("src_ip")}
sessions = {event.get("session") for event in events if event.get("session")}
failed_logins = event_types.count("cowrie.login.failed")
successful_logins = event_types.count("cowrie.login.success")
command_events = event_types.count("cowrie.command.input")
total_events = len(events)
source_count = len(source_ips)
session_count = len(sessions)

alerts = []
if callable(analyze_events):
    try:
        analysis_result = analyze_events(events)
        summary = analysis_result["summary"]
        alerts = analysis_result["alerts"]

        total_events = summary.get("total_events", total_events)
        source_count = summary.get("unique_source_ips", source_count)
        session_count = summary.get("unique_sessions", session_count)
        failed_logins = summary.get("failed_logins", failed_logins)
        successful_logins = summary.get("successful_logins", successful_logins)
        command_events = summary.get("command_events", command_events)
    except (KeyError, TypeError, ValueError) as error:
        st.warning(f"Analysis results were not in the expected format: {error}")
else:
    st.info("Analysis alerts will appear when src.analysis.analyze_events is available.")

valid_timestamps = []
for ev in events:
    t_val = ev.get("timestamp")
    if isinstance(t_val, str) and t_val.strip():
        parsed_dt = parse_timestamp(t_val) if callable(parse_timestamp) else None
        if parsed_dt:
            valid_timestamps.append(parsed_dt)
        else:
            try:
                pdt = pd.to_datetime(t_val)
                if pd.notna(pdt):
                    valid_timestamps.append(pdt)
            except Exception:
                pass

if valid_timestamps:
    latest_ts_obj = max(valid_timestamps)
    latest_ts_str = latest_ts_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
else:
    latest_ts_str = "No timestamp recorded"


# ---------------------------------------------------------------------------
# Section Rendering
# ---------------------------------------------------------------------------
render_header(
    database_name=DATABASE_FILE.name,
    total_events=total_events,
    latest_timestamp=latest_ts_str,
)

summary_metrics = {
    "total_events": total_events,
    "source_count": source_count,
    "session_count": session_count,
    "successful_logins": successful_logins,
    "failed_logins": failed_logins,
    "command_events": command_events,
}
render_kpi_cards(summary_metrics)

high_alerts = sum(1 for a in alerts if a.get("severity") == "high")
med_alerts = sum(1 for a in alerts if a.get("severity") == "medium")
low_alerts = sum(1 for a in alerts if a.get("severity") == "low")
render_posture_banner(total_events, high_alerts, med_alerts, low_alerts)

render_attack_activity_section(
    events=events,
    valid_timestamps=valid_timestamps,
    successful_logins=successful_logins,
    failed_logins=failed_logins,
)

render_alerts_section(alerts)

render_event_explorer(events)
