""" Reusable header, sidebar controls, KPI cards, and status components. """

import html
from pathlib import Path
import sqlite3
from typing import Any
import streamlit as st


def render_sidebar(database_file: Path, default_limit: int = 1000) -> int:
    """Render the sidebar controls and documentation.

    Returns:
        event_limit: Maximum number of events to retrieve from storage.
    """
    with st.sidebar:
        st.markdown("### Controls")
        st.caption("Local database connection and query parameters.")

        db_exists = database_file.exists()
        status_label = "Available" if db_exists else "Missing"
        st.markdown(f"**Database Status:** `{status_label}`")
        st.code(str(database_file), language="text")

        # Query total records stored in the SQLite database to make the limit transparent
        total_stored = None
        if db_exists:
            try:
                with sqlite3.connect(database_file) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM events")
                    total_stored = cur.fetchone()[0]
            except Exception:
                pass

        if total_stored is not None:
            st.caption(f"Database currently holds {total_stored:,} total records.")

        event_limit = st.slider(
            "Event retrieval limit",
            min_value=100,
            max_value=10000,
            value=default_limit,
            step=100,
            help=(
                "Maximum number of records retrieved from the database into memory for analysis. "
                "for larger event collections."
            ),
        )

        st.markdown("---")
        st.markdown("### Honeypot Architecture")
        st.markdown(
            """
            - **Decoy:** Cowrie SSH Honeypot
            - **Schema:** 9 Normalized Fields
            - **Storage:** SQLite (`data/honeypot.db`)
            - **Analysis:** Rule-based heuristics
            """
        )

        st.markdown("---")
        st.markdown("### Alert Severity Reference")
        st.markdown(
            """
            - **High:** Repeated login bursts (5 or more attempts in 5 minutes)
            - **Medium:** Download tools, permission changes, high command volume
            - **Low:** Simulated login notifications, reconnaissance queries
            """
        )
        st.caption("Cowrie recorded logins are simulated attacker interactions, not production host breaches.")

    return event_limit


def render_header(database_name: str, total_events: int, latest_timestamp: str):
    """Render the dashboard top banner and honest data status indicators."""
    clean_db_name = html.escape(database_name)
    clean_ts = html.escape(latest_timestamp)

    header_html = f"""
    <div class="soc-header">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
            <div>
                <h1 class="soc-title">Honeypot Cyberattack Intelligence</h1>
                <div class="soc-subtitle">SSH Threat Monitoring & Attack Behavior Analysis</div>
            </div>
            <div style="text-align: right;">
                <span class="status-pill">
                    <span class="status-dot"></span>
                    <span>Storage: Active</span>
                </span>
            </div>
        </div>
        <div class="status-bar">
            <span class="status-pill">
                <b>Data Source:</b> Static SQLite Snapshot (<code>{clean_db_name}</code>)
            </span>
            <span class="status-pill">
                <b>Loaded Records:</b> {total_events:,} events
            </span>
            <span class="status-pill">
                <b>Latest Event:</b> {clean_ts}
            </span>
            <span class="status-pill">
                <b>Sensor Decoy:</b> Cowrie SSH (Port 2222)
            </span>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_kpi_cards(metrics: dict[str, Any]):
    """Render the 6 key performance indicator metric cards."""
    st.markdown(
        """
        <div class="section-title">Security Overview</div>
        <div class="section-subtitle">
            High-level key metrics calculated from normalized honeypot storage
        </div>
        """,
        unsafe_allow_html=True,
    )

    kpi_cols = st.columns(6)

    kpi_definitions = [
        (
            "Total Events",
            f"{metrics.get('total_events', 0):,}",
            "Normalized Cowrie records",
            "kpi-accent-blue",
        ),
        (
            "Unique Source IPs",
            f"{metrics.get('source_count', 0):,}",
            "Distinct attacking hosts",
            "kpi-accent-teal",
        ),
        (
            "Unique Sessions",
            f"{metrics.get('session_count', 0):,}",
            "Active or closed sessions",
            "kpi-accent-indigo",
        ),
        (
            "Successful Logins",
            f"{metrics.get('successful_logins', 0):,}",
            "Simulated decoy entries",
            "kpi-accent-green",
        ),
        (
            "Failed Logins",
            f"{metrics.get('failed_logins', 0):,}",
            "Blocked authentication attempts",
            "kpi-accent-red",
        ),
        (
            "Command Events",
            f"{metrics.get('command_events', 0):,}",
            "Captured shell inputs",
            "kpi-accent-slate",
        ),
    ]

    for col, (label, value, caption, accent_class) in zip(kpi_cols, kpi_definitions):
        with col:
            card_html = f"""
            <div class="kpi-card {accent_class}">
                <div class="kpi-label">{html.escape(label)}</div>
                <div class="kpi-value">{html.escape(value)}</div>
                <div class="kpi-caption">{html.escape(caption)}</div>
            </div>
            """
            st.markdown(card_html, unsafe_allow_html=True)


def render_posture_banner(total_events: int, high_count: int, med_count: int, low_count: int):
    """Render the posture banner summarizing alert counts across threat tiers."""
    posture_html = f"""
    <div class="posture-banner">
        <div>
            <b>Security Status Posture:</b> &nbsp;
            <span style="color: var(--soc-text-muted);">
                Detection heuristics evaluated across {total_events:,} events
            </span>
        </div>
        <div class="posture-pills">
            <span class="badge badge-high">High: {high_count}</span>
            <span class="badge badge-medium">Medium: {med_count}</span>
            <span class="badge badge-low">Low: {low_count}</span>
        </div>
    </div>
    """
    st.markdown(posture_html, unsafe_allow_html=True)
