
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

NORMALIZED_FIELDS = {
    "timestamp", "eventid", "src_ip", "session",
    "protocol", "username", "input", "message", "extra",
}

# Words commonly found in field names that may contain sensitive information.
SENSITIVE_WORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "authorization",
    "api_key",
    "private_key",
)


def is_sensitive_field(key):
    """Check whether a field name might contain a secret."""

    # Convert the field name to lowercase so matching is case-insensitive.
    # Replace hyphens with underscores to handle names like "private-key".
    normalized_key = key.lower().replace("-", "_")

    # Return True if the field name contains a sensitive word,
    # ends with "_key", or is exactly "auth".
    return (
        any(word in normalized_key for word in SENSITIVE_WORDS)
        or normalized_key.endswith("_key")
        or normalized_key == "auth"
    )



def normalize_timestamp(value):
    """Convert a timestamp to UTC ISO 8601 format."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")

    except ValueError:
        return None


def normalize_event(raw_event):
    """Convert one raw Cowrie record to the agreed event schema."""
    if not isinstance(raw_event, dict):
        return None

    timestamp = normalize_timestamp(raw_event.get("timestamp"))
    eventid = raw_event.get("eventid")

    if timestamp is None:
        return None

    if not isinstance(eventid, str) or not eventid.strip():
        return None

    event = {
        "timestamp": timestamp,
        "eventid": eventid,
        "src_ip": raw_event.get("src_ip"),
        "session": raw_event.get("session"),
        "protocol": raw_event.get("protocol"),
        "username": raw_event.get("username"),
        "input": raw_event.get("input"),
        "message": raw_event.get("message"),
        "extra": {},
    }

    for key, value in raw_event.items():
        if key in NORMALIZED_FIELDS:
            continue

        if is_sensitive_field(key):
            continue

        if isinstance(value, (str, int, float, bool)) or value is None:
            event["extra"][key] = value

    return event


def read_events(log_path):
    """Read JSONL records, skipping malformed or unusable records."""
    events = []
    skipped = 0

    with open(log_path, "r", encoding="utf-8-sig") as log_file:
        for line in log_file:
            if not line.strip():
                continue

            try:
                raw_event = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            event = normalize_event(raw_event)

            if event is None:
                skipped += 1
                continue

            events.append(event)

    if skipped:
        logger.warning(
            "Skipped %d malformed or unusable Cowrie records.",
            skipped,
        )

    return events
