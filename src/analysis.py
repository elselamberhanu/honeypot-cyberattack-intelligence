"""Simple analysis rules for normalized Cowrie honeypot events.

The main function is analyze_events(events). It returns summary statistics
and alerts using the format agreed by the project team.

Important: this file only reads command text. It never runs commands.
Alerts are clues for investigation, not proof that an attack succeeded.
"""

from datetime import datetime, timedelta, timezone
import re

# These values come from the team's technical contract.
FAILED_LOGIN_LIMIT = 5
COMMAND_LIMIT = 20
WINDOW_MINUTES = 5

# Each pattern has a rule name, severity, pattern to look for, and explanation.
# These are simple text checks, not a complete way to understand shell commands.
RISKY_COMMANDS = [
    (
        "reconnaissance",
        "low",
        r"\bwhoami\b",
        "Command may reveal the current user identity.",
    ),
    (
        "reconnaissance",
        "low",
        r"\buname\b",
        "Command may reveal operating-system information.",
    ),
    (
        "reconnaissance",
        "low",
        r"\bcat\s+/etc/passwd\b",
        "Command attempts to read the local account list.",
    ),
    (
        "download",
        "medium",
        r"\bwget\b",
        "Command contains wget, which can download remote content.",
    ),
    (
        "download",
        "medium",
        r"\bcurl\b",
        "Command contains curl, which can retrieve remote content.",
    ),
    (
        "permission_change",
        "medium",
        r"\bchmod\b",
        "Command attempts to change file permissions.",
    ),
    (
        "destructive_command",
        "medium",
        r"\brm\s+-rf\b",
        "Command contains a recursive force-removal pattern.",
    ),
]


def parse_timestamp(value):
    """Convert an ISO timestamp to UTC; return None if it is not usable."""
    if not isinstance(value, str) or not value.strip():
        return None

    # Python understands +00:00; older timestamp data may use a trailing Z.
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return None

    # The contract says timestamps without a timezone should be treated as UTC.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def make_alert(rule, severity, event, description):
    """Create an alert with exactly the six fields required by the contract."""
    return {
        "rule": rule,
        "severity": severity,
        "src_ip": event.get("src_ip"),
        "session": event.get("session"),
        "timestamp": event.get("timestamp"),
        "description": description,
    }


def find_burst_alerts(events, event_type, group_field, limit, rule, severity,
                      description, allow_equal=True):
    """Find one alert per IP/session with too many events in five minutes.

    For failed logins, reaching the limit is enough. For command volume, the
    contract says the count must be greater than 20, so allow_equal is False.
    """
    groups = {}
    window = timedelta(minutes=WINDOW_MINUTES)

    # Keep only matching events that have a valid time and group value.
    for event in events:
        if event.get("eventid") != event_type:
            continue

        group_value = event.get(group_field)
        event_time = parse_timestamp(event.get("timestamp"))
        if not group_value or event_time is None:
            continue

        if group_value not in groups:
            groups[group_value] = []
        groups[group_value].append((event_time, event))

    alerts = []

    # Check each IP/session separately, in timestamp order.
    for group_events in groups.values():
        group_events.sort(key=lambda item: item[0])

        first_in_window = 0
        for right in range(len(group_events)):
            current_time = group_events[right][0]

            # Move the start of the window forward until it is no more than
            # five minutes before the current event.
            while current_time - group_events[first_in_window][0] > window:
                first_in_window += 1

            count = right - first_in_window + 1
            if (allow_equal and count >= limit) or (not allow_equal and count > limit):
                event = group_events[right][1]
                alerts.append(make_alert(rule, severity, event, description))
                break  # Only one burst alert per IP/session.

    return alerts


def analyze_events(events):
    """Return summary counts and alerts for a list of normalized events."""
    # Ignore invalid list entries without changing the original input.
    if events is None:
        events = []
    try:
        event_list = [event for event in events if isinstance(event, dict)]
    except TypeError:
        event_list = []

    # Count distinct non-empty source IPs and session IDs.
    source_ips = set()
    sessions = set()
    for event in event_list:
        ip = event.get("src_ip")
        session = event.get("session")
        if isinstance(ip, str) and ip.strip():
            source_ips.add(ip)
        if isinstance(session, str) and session.strip():
            sessions.add(session)

    # Count the event types needed by the dashboard.
    successful_logins = sum(
        event.get("eventid") == "cowrie.login.success" for event in event_list
    )
    failed_logins = sum(
        event.get("eventid") == "cowrie.login.failed" for event in event_list
    )
    command_events = sum(
        event.get("eventid") == "cowrie.command.input" for event in event_list
    )

    summary = {
        "total_events": len(event_list),
        "unique_source_ips": len(source_ips),
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "command_events": command_events,
        "unique_sessions": len(sessions),
    }

    alerts = []

    # Rule A: five or more failed logins from one IP within five minutes.
    alerts.extend(find_burst_alerts(
        event_list,
        "cowrie.login.failed",
        "src_ip",
        FAILED_LOGIN_LIMIT,
        "failed_login_burst",
        "high",
        "Five or more failed login events from one source within a rolling five-minute window.",
    ))

    # Rule B: make a low-severity alert for every successful Cowrie login.
    # A successful Cowrie login is simulated; it does not prove real access.
    for event in event_list:
        if event.get("eventid") == "cowrie.login.success":
            alerts.append(make_alert(
                "successful_simulated_login",
                "low",
                event,
                "Cowrie recorded a successful simulated login; this does not prove a real system was compromised.",
            ))

    # Rule C: search command text for the patterns listed at the top of this file.
    # Stop after the first match so one command does not create duplicate alerts.
    for event in event_list:
        if event.get("eventid") != "cowrie.command.input":
            continue

        command = event.get("input")
        if not isinstance(command, str):
            continue

        for rule, severity, pattern, description in RISKY_COMMANDS:
            if re.search(pattern, command, re.IGNORECASE):
                alerts.append(make_alert(rule, severity, event, description))
                break

    # Rule D: more than 20 commands in one session within five minutes.
    alerts.extend(find_burst_alerts(
        event_list,
        "cowrie.command.input",
        "session",
        COMMAND_LIMIT,
        "high_command_volume",
        "medium",
        "More than 20 command events were recorded in one session within a rolling five-minute window.",
        allow_equal=False,
    ))

    # Put alerts in time order to make them easier to read.
    alerts.sort(key=lambda alert: (
        parse_timestamp(alert.get("timestamp"))
        or datetime.max.replace(tzinfo=timezone.utc),
        alert.get("rule") or "",
    ))

    return {"summary": summary, "alerts": alerts}