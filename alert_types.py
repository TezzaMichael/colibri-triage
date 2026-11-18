"""Alert type classification used to route enrichment and LLM analysis prompts."""

from typing import Any

# Lowercase substrings matched against alert metadata to identify auth-related events.
AUTH_KEYWORDS = (
    "login",
    "log in",
    "logon",
    "log on",
    "sign-in",
    "signin",
    "sign in",
    "authentication",
    "authenticat",
    "impossible travel",
    "atypical travel",
    "brute force",
    "brute-force",
    "password spray",
    "mfa",
    "multi-factor",
    "2fa",
    "vpn",
    "unfamiliar sign",
    "risky sign",
    "unusual country",
    "unusual location",
    "account takeover",
    "failed logon",
)

_TEXT_KEYS = (
    "name",
    "alert_name",
    "title",
    "description",
    "desc",
    "category",
    "category_name",
    "class_name",
    "alert_type",
    "source",
    "mitre_technique_id_and_name",
    "mitre_tactic_id_and_name",
)

_FINDING_KEYS = ("title", "desc", "types")


def _extract_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_extract_strings(item))
        return result
    return []


def _collect_text(alert: dict[str, Any]) -> str:
    """Flatten relevant string fields into a single lowercase search buffer."""
    parts: list[str] = []
    for key in _TEXT_KEYS:
        parts.extend(_extract_strings(alert.get(key)))

    finding = alert.get("finding_info")
    if isinstance(finding, dict):
        for key in _FINDING_KEYS:
            parts.extend(_extract_strings(finding.get(key)))

    return " | ".join(parts).lower()


def detect_alert_type(raw: dict[str, Any] | list[dict[str, Any]]) -> tuple[str, str | None]:
    """Classify an alert (or list of alerts in a Cortex case) by matching keywords.

    Defaults to ("endpoint", None) when no authentication indicators are found.
    """
    alerts = raw if isinstance(raw, list) else [raw]
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        text = _collect_text(alert)
        for keyword in AUTH_KEYWORDS:
            if keyword in text:
                return "authentication", keyword

    return "endpoint", None