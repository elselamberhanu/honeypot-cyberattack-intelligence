"""Visualization components for honeypot telemetry and attack activity.

Includes timeline, event types, login outcomes, source IPs, and command activity.
"""

from collections import Counter
from datetime import datetime
import altair as alt
import pandas as pd
import streamlit as st

from .styles import apply_chart_theme, get_chart_palette, get_current_theme_mode


def render_attack_activity_section(
    events: list[dict],
    valid_timestamps: list[datetime],
    successful_logins: int,
    failed_logins: int,
):
    """Render the Attack Activity & Threat Telemetry section with two-way Graph/Table switches."""
    st.markdown(
        """
        <div class="section-title">Attack Activity & Threat Telemetry</div>
        <div class="section-subtitle">
            Visual distribution of honeypot events, login dynamics, and attacker actions
        </div>
        """,
        unsafe_allow_html=True,
    )

    theme_mode = get_current_theme_mode()
    palette = get_chart_palette(theme_mode)

    # Row 1: Events over time (3 cols) and Event types distribution (2 cols)
    col1, col2 = st.columns([3, 2])

    # -------------------------------------------------------------------------
    # 1. Events Over Time
    # -------------------------------------------------------------------------
    with col1:
        head_col1, head_col2 = st.columns([3, 1])
        with head_col1:
            st.markdown(
                """
                <div class="chart-card-header">Events Over Time</div>
                <div class="chart-card-caption">Activity frequency timeline grouped by timestamp interval</div>
                """,
                unsafe_allow_html=True,
            )
        with head_col2:
            view_timeline = st.segmented_control(
                "View mode for events over time",
                options=["Graph", "Table"],
                default="Graph",
                key="view_events_over_time",
                label_visibility="collapsed",
            ) or "Graph"

        if valid_timestamps:
            min_ts = min(valid_timestamps)
            max_ts = max(valid_timestamps)
            span_seconds = (max_ts - min_ts).total_seconds()

            time_mode = st.radio(
                "Time aggregation interval:",
                options=["Auto", "Minute", "Hour", "Day"],
                horizontal=True,
                index=0,
                key="timeline_interval",
                label_visibility="collapsed",
            )

            if time_mode == "Auto":
                if span_seconds <= 7200:  # <= 2 hours
                    chosen_interval = "minute"
                elif span_seconds <= 86400 * 3:  # <= 3 days
                    chosen_interval = "hour"
                else:
                    chosen_interval = "day"
            else:
                chosen_interval = time_mode.lower()

            time_counts = Counter()
            for ts_dt in valid_timestamps:
                if chosen_interval == "minute":
                    key = ts_dt.strftime("%Y-%m-%d %H:%M UTC")
                elif chosen_interval == "hour":
                    key = ts_dt.strftime("%Y-%m-%d %H:00 UTC")
                else:
                    key = ts_dt.strftime("%Y-%m-%d UTC")
                time_counts[key] += 1

            df_timeline = pd.DataFrame([
                {"Interval": k, "Event Count": v}
                for k, v in sorted(time_counts.items())
            ])

            if view_timeline == "Table":
                st.dataframe(df_timeline, width="stretch", hide_index=True)
            else:
                area_chart = alt.Chart(df_timeline).mark_area(
                    line={"color": palette["timeline_line"], "width": 2},
                    color=alt.Gradient(
                        gradient="linear",
                        stops=[
                            alt.GradientStop(color=palette["timeline_fill_start"], offset=0),
                            alt.GradientStop(color=palette["timeline_fill_end"], offset=1),
                        ],
                        x1=1,
                        x2=1,
                        y1=1,
                        y2=0,
                    ),
                    point={"color": palette["timeline_point"], "size": 32, "filled": True},
                ).encode(
                    x=alt.X("Interval:N", title="Timestamp (UTC)", axis=alt.Axis(labelAngle=-35)),
                    y=alt.Y("Event Count:Q", title="Events Recorded"),
                    tooltip=["Interval", "Event Count"],
                ).properties(height=260)

                st.altair_chart(apply_chart_theme(area_chart, theme_mode), width="stretch")
        else:
            st.info("No usable timestamps were found to render the events timeline.")

    # -------------------------------------------------------------------------
    # 2. Event Types Distribution
    # -------------------------------------------------------------------------
    with col2:
        head_col1, head_col2 = st.columns([3, 1])
        with head_col1:
            st.markdown(
                """
                <div class="chart-card-header">Event Types Distribution</div>
                <div class="chart-card-caption">Proportion of normalized Cowrie event IDs recorded</div>
                """,
                unsafe_allow_html=True,
            )
        with head_col2:
            view_types = st.segmented_control(
                "View mode for event types",
                options=["Graph", "Table"],
                default="Graph",
                key="view_event_types",
                label_visibility="collapsed",
            ) or "Graph"

        type_counts = Counter(str(event.get("eventid") or "unknown") for event in events)
        df_types = pd.DataFrame([
            {"Event Type": k, "Count": v}
            for k, v in type_counts.most_common()
        ])

        if view_types == "Table":
            st.dataframe(df_types, width="stretch", hide_index=True)
        else:
            types_chart = alt.Chart(df_types).mark_bar(
                cornerRadiusEnd=3,
                color=palette["event_types"],
            ).encode(
                y=alt.Y("Event Type:N", sort="-x", title=None),
                x=alt.X("Count:Q", title="Total Occurrences"),
                tooltip=["Event Type", "Count"],
            ).properties(height=290)

            st.altair_chart(apply_chart_theme(types_chart, theme_mode), width="stretch")

    # Row 2: Login outcomes, Top source IPs, Frequent commands
    col_l1, col_l2, col_l3 = st.columns(3)

    # -------------------------------------------------------------------------
    # 3. Login Outcomes
    # -------------------------------------------------------------------------
    with col_l1:
        head_col1, head_col2 = st.columns([2.5, 1])
        with head_col1:
            st.markdown(
                """
                <div class="chart-card-header">Login Outcomes</div>
                <div class="chart-card-caption">Simulated successful vs failed authentication</div>
                """,
                unsafe_allow_html=True,
            )
        with head_col2:
            view_logins = st.segmented_control(
                "View mode for logins",
                options=["Graph", "Table"],
                default="Graph",
                key="view_login_outcomes",
                label_visibility="collapsed",
            ) or "Graph"

        df_logins = pd.DataFrame([
            {"Outcome": "Simulated Success", "Attempts": successful_logins, "ColorCategory": "Success"},
            {"Outcome": "Failed Logins", "Attempts": failed_logins, "ColorCategory": "Failed"},
        ])

        if successful_logins == 0 and failed_logins == 0:
            st.info("No login attempt records found in the current dataset.")
        else:
            if view_logins == "Table":
                st.dataframe(df_logins[["Outcome", "Attempts"]], width="stretch", hide_index=True)
            else:
                logins_chart = alt.Chart(df_logins).mark_bar(
                    cornerRadiusEnd=3,
                ).encode(
                    x=alt.X("Outcome:N", title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("Attempts:Q", title="Attempt Count"),
                    color=alt.Color(
                        "ColorCategory:N",
                        scale=alt.Scale(
                            domain=["Success", "Failed"],
                            range=[palette["login_success"], palette["login_failed"]],
                        ),
                        legend=None,
                    ),
                    tooltip=["Outcome", "Attempts"],
                ).properties(height=230)

                st.altair_chart(apply_chart_theme(logins_chart, theme_mode), width="stretch")
            st.caption("Note: Honeypot successful logins are simulated by Cowrie to observe attacker commands.")

    # -------------------------------------------------------------------------
    # 4. Top Source IPs
    # -------------------------------------------------------------------------
    with col_l2:
        head_col1, head_col2 = st.columns([2.5, 1])
        with head_col1:
            st.markdown(
                """
                <div class="chart-card-header">Top Source IPs</div>
                <div class="chart-card-caption">Most active remote IP addresses interacting with honeypot</div>
                """,
                unsafe_allow_html=True,
            )
        with head_col2:
            view_ips = st.segmented_control(
                "View mode for source IPs",
                options=["Graph", "Table"],
                default="Graph",
                key="view_top_source_ips",
                label_visibility="collapsed",
            ) or "Graph"

        ip_counts = Counter(event.get("src_ip") for event in events if event.get("src_ip"))
        if ip_counts:
            df_ips = pd.DataFrame([
                {"Source IP": ip, "Events": count}
                for ip, count in ip_counts.most_common(8)
            ])

            if view_ips == "Table":
                st.dataframe(df_ips, width="stretch", hide_index=True)
            else:
                ips_chart = alt.Chart(df_ips).mark_bar(
                    cornerRadiusEnd=3,
                    color=palette["source_ips"],
                ).encode(
                    y=alt.Y("Source IP:N", sort="-x", title=None),
                    x=alt.X("Events:Q", title="Events Recorded"),
                    tooltip=["Source IP", "Events"],
                ).properties(height=230)

                st.altair_chart(apply_chart_theme(ips_chart, theme_mode), width="stretch")
        else:
            st.info("No source IP addresses recorded in the loaded events.")

    # -------------------------------------------------------------------------
    # 5. Frequent Commands
    # -------------------------------------------------------------------------
    with col_l3:
        head_col1, head_col2 = st.columns([2.5, 1])
        with head_col1:
            st.markdown(
                """
                <div class="chart-card-header">Frequent Commands</div>
                <div class="chart-card-caption">Observed shell inputs entered during sessions</div>
                """,
                unsafe_allow_html=True,
            )
        with head_col2:
            view_cmds = st.segmented_control(
                "View mode for frequent commands",
                options=["Graph", "Table"],
                default="Graph",
                key="view_frequent_commands",
                label_visibility="collapsed",
            ) or "Graph"

        cmd_counts = Counter(
            str(event.get("input"))
            for event in events
            if event.get("input") and str(event.get("input")).strip()
        )

        if cmd_counts:
            df_cmds = pd.DataFrame([
                {"Command": cmd, "Executions": count}
                for cmd, count in cmd_counts.most_common(8)
            ])

            if view_cmds == "Table":
                st.dataframe(df_cmds, width="stretch", hide_index=True)
            else:
                cmds_chart = alt.Chart(df_cmds).mark_bar(
                    cornerRadiusEnd=3,
                    color=palette["commands"],
                ).encode(
                    y=alt.Y("Command:N", sort="-x", title=None),
                    x=alt.X("Executions:Q", title="Execution Count"),
                    tooltip=["Command", "Executions"],
                ).properties(height=230)

                st.altair_chart(apply_chart_theme(cmds_chart, theme_mode), width="stretch")
        else:
            st.info("No shell command inputs recorded in the current dataset.")
