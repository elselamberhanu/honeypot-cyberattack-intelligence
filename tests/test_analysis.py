"""Beginner-friendly tests for the analysis module.

Each test creates fake normalized events, runs analyze_events(), and checks
one expected result. The IP addresses and commands below are examples only.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from src.analysis import analyze_events


BASE_TIME = datetime(2026, 10, 16, 8, 0, tzinfo=timezone.utc)


def make_event(
    eventid="cowrie.session.connect",
    *,
    minutes=0,
    seconds=0,
    src_ip="192.0.2.10",
    session="session-1",
    username=None,
    command=None,
    timestamp=None,
):
    """Build a normalized event with all nine agreed fields."""
    if timestamp is None:
        timestamp = (
            BASE_TIME + timedelta(minutes=minutes, seconds=seconds)
        ).isoformat().replace("+00:00", "Z")

    return {
        "timestamp": timestamp,
        "eventid": eventid,
        "src_ip": src_ip,
        "session": session,
        "protocol": "ssh",
        "username": username,
        "input": command,
        "message": None,
        "extra": {},
    }


def find_alerts(result, rule):
    """Return only alerts whose rule name matches the one being tested."""
    return [alert for alert in result["alerts"] if alert["rule"] == rule]


def test_empty_list_returns_complete_empty_result():
    result = analyze_events([])

    assert result == {
        "summary": {
            "total_events": 0,
            "unique_source_ips": 0,
            "successful_logins": 0,
            "failed_logins": 0,
            "command_events": 0,
            "unique_sessions": 0,
        },
        "alerts": [],
    }


def test_none_input_is_handled_as_empty():
    assert analyze_events(None)["summary"]["total_events"] == 0
    assert analyze_events(None)["alerts"] == []


def test_summary_counts_events_ips_sessions_and_event_types():
    events = [
        make_event("cowrie.login.failed", src_ip="192.0.2.10", session="s1"),
        make_event("cowrie.login.failed", minutes=1, src_ip="192.0.2.10", session="s1"),
        make_event("cowrie.login.success", minutes=2, src_ip="192.0.2.11", session="s2"),
        make_event("cowrie.command.input", minutes=3, src_ip="192.0.2.11", session="s2", command="pwd"),
        make_event("cowrie.session.connect", minutes=4, src_ip=None, session=None),
    ]

    summary = analyze_events(events)["summary"]

    assert summary == {
        "total_events": 5,
        "unique_source_ips": 2,
        "successful_logins": 1,
        "failed_logins": 2,
        "command_events": 1,
        "unique_sessions": 2,
    }


def test_summary_ignores_blank_source_ips_and_sessions():
    events = [
        make_event(src_ip=None, session=None),
        make_event(minutes=1, src_ip="", session=""),
        make_event(minutes=2, src_ip="192.0.2.10", session="s1"),
    ]

    summary = analyze_events(events)["summary"]

    assert summary["unique_source_ips"] == 1
    assert summary["unique_sessions"] == 1


def test_failed_login_burst_triggers_at_five_events():
    events = [
        make_event("cowrie.login.failed", minutes=i, src_ip="192.0.2.10")
        for i in range(5)
    ]

    alerts = find_alerts(analyze_events(events), "failed_login_burst")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["src_ip"] == "192.0.2.10"


def test_failed_login_rule_does_not_trigger_below_five():
    events = [
        make_event("cowrie.login.failed", minutes=i, src_ip="192.0.2.10")
        for i in range(4)
    ]

    assert find_alerts(analyze_events(events), "failed_login_burst") == []


def test_failed_login_window_includes_exact_five_minute_boundary():
    # Five events span exactly five minutes: 08:00, 08:01, 08:02, 08:03, 08:05.
    events = [
        make_event("cowrie.login.failed", minutes=minute, src_ip="192.0.2.10")
        for minute in (0, 1, 2, 3, 5)
    ]

    assert len(find_alerts(analyze_events(events), "failed_login_burst")) == 1


def test_failed_logins_outside_one_rolling_window_do_not_trigger():
    events = [
        make_event("cowrie.login.failed", minutes=0, src_ip="192.0.2.10"),
        make_event("cowrie.login.failed", minutes=6, src_ip="192.0.2.10"),
        make_event("cowrie.login.failed", minutes=12, src_ip="192.0.2.10"),
        make_event("cowrie.login.failed", minutes=18, src_ip="192.0.2.10"),
        make_event("cowrie.login.failed", minutes=24, src_ip="192.0.2.10"),
    ]

    assert find_alerts(analyze_events(events), "failed_login_burst") == []


def test_failed_login_bursts_are_grouped_by_source_ip():
    events = []
    for ip in ("192.0.2.10", "192.0.2.11"):
        events.extend(
            make_event("cowrie.login.failed", minutes=i, src_ip=ip)
            for i in range(5)
        )

    alerts = find_alerts(analyze_events(events), "failed_login_burst")

    assert len(alerts) == 2
    assert {alert["src_ip"] for alert in alerts} == {"192.0.2.10", "192.0.2.11"}


def test_failed_login_rule_ignores_events_without_source_ip():
    events = [
        make_event("cowrie.login.failed", minutes=i, src_ip=None)
        for i in range(5)
    ]

    assert find_alerts(analyze_events(events), "failed_login_burst") == []


def test_successful_login_is_counted_and_generates_low_alert():
    event = make_event(
        "cowrie.login.success",
        username="sample_user",
        src_ip="192.0.2.10",
        session="s1",
    )

    result = analyze_events([event])
    alerts = find_alerts(result, "successful_simulated_login")

    assert result["summary"]["successful_logins"] == 1
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "low"
    assert alerts[0]["session"] == "s1"
    assert "does not prove" in alerts[0]["description"]


@pytest.mark.parametrize(
    ("command", "expected_rule", "expected_severity"),
    [
        ("whoami", "reconnaissance", "low"),
        ("uname -a", "reconnaissance", "low"),
        ("cat /etc/passwd", "reconnaissance", "low"),
        ("wget https://example.invalid/file", "download", "medium"),
        ("curl https://example.invalid/file", "download", "medium"),
        ("chmod 777 file.sh", "permission_change", "medium"),
        ("rm -rf /tmp/example", "destructive_command", "medium"),
    ],
)
def test_risky_command_patterns(command, expected_rule, expected_severity):
    event = make_event("cowrie.command.input", command=command)

    alerts = find_alerts(analyze_events([event]), expected_rule)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == expected_severity
    assert alerts[0]["src_ip"] == event["src_ip"]


def test_command_without_risky_pattern_does_not_alert():
    event = make_event("cowrie.command.input", command="pwd")

    result = analyze_events([event])

    assert result["summary"]["command_events"] == 1
    assert result["alerts"] == []


def test_command_input_is_never_executed_or_modified():
    command = "whoami"
    event = make_event("cowrie.command.input", command=command)
    original = deepcopy(event)

    analyze_events([event])

    assert event == original
    assert event["input"] == command


def test_high_command_volume_triggers_above_twenty():
    events = [
        make_event(
            "cowrie.command.input",
            seconds=i,
            src_ip="192.0.2.10",
            session="busy-session",
            command="pwd",
        )
        for i in range(21)
    ]

    alerts = find_alerts(analyze_events(events), "high_command_volume")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["session"] == "busy-session"


def test_high_command_volume_does_not_trigger_at_exactly_twenty():
    events = [
        make_event(
            "cowrie.command.input",
            seconds=i,
            session="busy-session",
            command="pwd",
        )
        for i in range(20)
    ]

    assert find_alerts(analyze_events(events), "high_command_volume") == []


def test_high_command_volume_groups_by_session():
    events = []
    for session in ("session-a", "session-b"):
        events.extend(
            make_event(
                "cowrie.command.input",
                seconds=i,
                session=session,
                command="pwd",
            )
            for i in range(11)
        )

    # Each session has only 11 commands, so neither should trigger.
    assert find_alerts(analyze_events(events), "high_command_volume") == []


def test_high_command_volume_ignores_missing_session():
    events = [
        make_event(
            "cowrie.command.input",
            seconds=i,
            session=None,
            command="pwd",
        )
        for i in range(25)
    ]

    assert find_alerts(analyze_events(events), "high_command_volume") == []


def test_invalid_timestamps_are_safe_and_excluded_from_windows():
    events = [
        make_event(
            "cowrie.login.failed",
            timestamp="not-a-timestamp",
            src_ip="192.0.2.10",
        )
        for _ in range(5)
    ]

    assert find_alerts(analyze_events(events), "failed_login_burst") == []


def test_timezone_offsets_are_compared_as_utc():
    # Different local offsets represent five timestamps only four minutes apart
    # after conversion to UTC.
    events = [
        make_event(
            "cowrie.login.failed",
            timestamp=f"2026-10-16T11:0{i}:00+03:00",
            src_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    assert len(find_alerts(analyze_events(events), "failed_login_burst")) == 1


def test_alerts_have_exact_required_fields():
    events = [
        make_event("cowrie.login.success", username="sample_user"),
        make_event("cowrie.command.input", command="whoami", minutes=1),
    ]

    result = analyze_events(events)
    required = {"rule", "severity", "src_ip", "session", "timestamp", "description"}

    assert result["alerts"]
    for alert in result["alerts"]:
        assert set(alert) == required


def test_input_events_are_not_modified():
    events = [
        make_event("cowrie.login.failed", minutes=i)
        for i in range(5)
    ]
    original = deepcopy(events)

    analyze_events(events)

    assert events == original


def test_alerts_are_sorted_by_timestamp_then_rule():
    events = [
        make_event("cowrie.login.success", minutes=2, username="sample_user"),
        make_event("cowrie.command.input", minutes=1, command="whoami"),
    ]

    alerts = analyze_events(events)["alerts"]
    timestamps = [alert["timestamp"] for alert in alerts]

    assert timestamps == sorted(timestamps)