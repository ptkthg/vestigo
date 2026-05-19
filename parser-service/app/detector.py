import re
import json
from enum import Enum


class LogFormat(str, Enum):
    WINDOWS_EVENT_XML = "windows_event_xml"
    WINDOWS_EVENT_JSON = "windows_event_json"
    SYSLOG_RFC5424 = "syslog_rfc5424"
    SYSLOG_RFC3164 = "syslog_rfc3164"
    CEF = "cef"
    LEEF = "leef"
    JSON_GENERIC = "json_generic"
    FREE_TEXT = "free_text"


_RFC5424 = re.compile(r"^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T")
_RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    re.IGNORECASE,
)
_WIN_EVENT_XML = re.compile(r"<Event[\s>]", re.IGNORECASE)
_WIN_EVENT_JSON_KEYS = {"EventID", "TimeCreated", "EventRecordID", "Channel", "Provider"}


def detect_format(raw: str) -> LogFormat:
    raw = raw.strip()

    if raw.startswith("CEF:"):
        return LogFormat.CEF

    if raw.startswith("LEEF:"):
        return LogFormat.LEEF

    if _WIN_EVENT_XML.search(raw[:200]):
        return LogFormat.WINDOWS_EVENT_XML

    if _RFC5424.match(raw):
        return LogFormat.SYSLOG_RFC5424

    if _RFC3164.match(raw):
        return LogFormat.SYSLOG_RFC3164

    if raw.startswith(("{", "[")):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                if _WIN_EVENT_JSON_KEYS & data.keys():
                    return LogFormat.WINDOWS_EVENT_JSON
                return LogFormat.JSON_GENERIC
        except (json.JSONDecodeError, ValueError):
            pass

    return LogFormat.FREE_TEXT
