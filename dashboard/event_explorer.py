"""Event exploration and raw record inspection component.

Provides multi-field filtering, compact table browsing, and individual event payload viewing.
"""

import pandas as pd
import streamlit as st


def render_event_explorer(events: list[dict]):
    """Render the Event Explorer and Payload Inspector section."""
    st.markdown(
        """
        <div class="section-title">Event Explorer</div>
        <div class="section-subtitle">
            Interactive filtering, inspection of Cowrie events, and full JSON payload viewing
        </div>
        """,
        unsafe_allow_html=True,
    )

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([2, 2, 1.5, 2.5])

    all_event_types = sorted(list({str(e.get("eventid") or "") for e in events if e.get("eventid")}))
    with filter_col1:
        selected_event_types = st.multiselect(
            "Filter by Event Type:",
            options=all_event_types,
            default=[],
            placeholder="All event types",
        )

    all_source_ips = sorted(list({str(e.get("src_ip") or "") for e in events if e.get("src_ip")}))
    with filter_col2:
        selected_ips = st.multiselect(
            "Filter by Source IP:",
            options=all_source_ips,
            default=[],
            placeholder="All source IPs",
        )

    all_protocols = sorted(list({str(e.get("protocol") or "") for e in events if e.get("protocol")}))
    with filter_col3:
        selected_protocols = st.multiselect(
            "Filter Protocol:",
            options=all_protocols,
            default=[],
            placeholder="All protocols",
        )

    with filter_col4:
        search_query = st.text_input(
            "Search events:",
            placeholder="Search command, user, session, message...",
        ).strip().lower()

    filtered_events = list(reversed(events))

    if selected_event_types:
        filtered_events = [e for e in filtered_events if e.get("eventid") in selected_event_types]

    if selected_ips:
        filtered_events = [e for e in filtered_events if e.get("src_ip") in selected_ips]

    if selected_protocols:
        filtered_events = [e for e in filtered_events if e.get("protocol") in selected_protocols]

    if search_query:
        filtered_events = [
            e for e in filtered_events
            if search_query in str(e.get("input") or "").lower()
            or search_query in str(e.get("username") or "").lower()
            or search_query in str(e.get("session") or "").lower()
            or search_query in str(e.get("message") or "").lower()
            or search_query in str(e.get("src_ip") or "").lower()
        ]

    st.caption(f"Showing {len(filtered_events)} of {len(events)} total events (newest first)")

    if filtered_events:
        explorer_table_data = [
            {
                "Timestamp": ev.get("timestamp"),
                "Event Type": ev.get("eventid"),
                "Source IP": ev.get("src_ip"),
                "Protocol": ev.get("protocol"),
                "Username": ev.get("username"),
                "Command / Input": ev.get("input"),
                "Session": ev.get("session"),
                "Message": ev.get("message"),
            }
            for ev in filtered_events
        ]
        st.dataframe(
            pd.DataFrame(explorer_table_data),
            width="stretch",
            hide_index=True,
        )
    else:
        st.warning("No events match the selected filter criteria.")

    with st.expander("Event Detail Inspector (Full JSON Payload & Extra Fields)", expanded=False):
        if filtered_events:
            record_indices = list(range(len(filtered_events)))
            selected_record_idx = st.selectbox(
                "Select an event record to inspect:",
                options=record_indices,
                format_func=lambda i: (
                    f"[{i + 1}] {filtered_events[i].get('timestamp')} | "
                    f"{filtered_events[i].get('eventid')} | IP: {filtered_events[i].get('src_ip') or 'None'}"
                ),
            )

            chosen_ev = filtered_events[selected_record_idx]
            detail_col1, detail_col2 = st.columns([1, 1])

            with detail_col1:
                st.markdown("##### Normalized Standard Fields")
                st.write({
                    "timestamp": chosen_ev.get("timestamp"),
                    "eventid": chosen_ev.get("eventid"),
                    "src_ip": chosen_ev.get("src_ip"),
                    "session": chosen_ev.get("session"),
                    "protocol": chosen_ev.get("protocol"),
                    "username": chosen_ev.get("username"),
                    "input": chosen_ev.get("input"),
                    "message": chosen_ev.get("message"),
                })

            with detail_col2:
                st.markdown("##### Extra Metadata Payload (extra)")
                st.json(chosen_ev.get("extra") or {})
        else:
            st.write("No events available to inspect.")
