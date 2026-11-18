"""Build sanitized customer and GeoIP context for authentication alerts.

Expected environment variables:
    ENRICH_URL            Customer enrichment endpoint (default: https://enrich.cyberlys.net/colibri_api.php?action=customer)
    ENRICH_TOKEN          Bearer token for the enrichment endpoint
    ENRICH_HEADERS        Optional JSON object of additional HTTP headers
    ENRICH_BODY_TEMPLATE  JSON payload template using "{customer}" placeholder
    CUSTOMER_MAP          Optional JSON mapping {"<client_or_site>": "<customer_code>"}
    HOME_COUNTRIES        Comma-separated home countries requiring no travel note (default: IT,ITALY,ITALIA)
    GEOIP_DB              Path to a MaxMind GeoLite2 City/Country .mmdb file (preferred over API)
    IPINFO_TOKEN          Optional ipinfo.io fallback token
"""

import ipaddress
import json
import os
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import requests

from normalizer import CortexToECSNormalizer, SentinelOneToECSNormalizer
from sanitizer import AdvancedTelemetrySanitizer

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
COUNTRY_KEYS = {"action_country", "country", "country_code", "country_name"}

RULES_TEXT = (
    "RULES: use ONLY the geolocation listed above for the country of an IP; never guess it. "
    "If a geolocation is missing, say it could not be verified. A login from a country that the "
    "customer notes describe as legitimate for this user is expected behavior."
)

_READERS: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Alert Extraction Helpers
# ---------------------------------------------------------------------------
def _as_list(raw: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    return raw if isinstance(raw, list) else [raw]


def _walk_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for val in obj.values():
            yield from _walk_strings(val)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_strings(item)
    elif isinstance(obj, str):
        yield obj


def normalized_user(console: str, raw_alert: dict[str, Any]) -> str | None:
    """Extract the username as produced by the ECS normalizer so pseudonyms match."""
    normalizer = CortexToECSNormalizer() if console == "Cortex XDR" else SentinelOneToECSNormalizer()
    try:
        return ((normalizer.normalize(raw_alert).get("user") or {}).get("name")) or None
    except Exception:
        return None


def _local(value: str) -> str:
    """Strip domain prefix/suffix ('DOMAIN\\user' or 'user@domain' -> 'user')."""
    value = value.split("\\")[-1]
    return value.split("@")[0].strip().lower()


def alert_identities(console: str, raw_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect all email addresses, normalized usernames, and local parts from the alert."""
    emails: set[str] = set()
    names: list[str] = []

    for raw in raw_list:
        for text in _walk_strings(raw):
            emails.update(e.lower() for e in EMAIL_RE.findall(text))
        name = normalized_user(console, raw)
        if name and name not in names:
            names.append(name)

    locals_ = {_local(e) for e in emails} | {_local(n) for n in names}
    return {
        "emails": emails,
        "locals": {loc for loc in locals_ if loc},
        "names": names,
    }


def public_ips(raw_list: list[dict[str, Any]]) -> list[str]:
    """Return unique globally routable IPv4 addresses found in the alert payload."""
    found: list[str] = []
    for raw in raw_list:
        for text in _walk_strings(raw):
            for match in IPV4_RE.findall(text):
                try:
                    ip = ipaddress.ip_address(match)
                except ValueError:
                    continue
                if ip.is_global and match not in found:
                    found.append(match)
    return found


def alert_countries(raw_list: list[dict[str, Any]]) -> list[str]:
    """Extract non-empty country values already embedded in the raw alert."""
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key in COUNTRY_KEYS and isinstance(val, str):
                    cleaned = val.strip()
                    if cleaned and cleaned.upper() not in ("UNKNOWN", "N/A", "NONE") and cleaned not in found:
                        found.append(cleaned)
                else:
                    walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for raw in raw_list:
        walk(raw)
    return found


# ---------------------------------------------------------------------------
# GeoIP Lookup
# ---------------------------------------------------------------------------
def geo_lookup(ip: str) -> dict[str, str | None] | None:
    """Resolve an IP to {country, iso, city} using a local MaxMind DB or ipinfo.io fallback."""
    db_path = os.getenv("GEOIP_DB")
    if db_path and os.path.exists(db_path):
        try:
            import geoip2.database

            if db_path not in _READERS:
                _READERS[db_path] = geoip2.database.Reader(db_path)
            reader = _READERS[db_path]
            is_country_db = "country" in reader.metadata().database_type.lower()
            resp = reader.country(ip) if is_country_db else reader.city(ip)
            return {
                "country": resp.country.name,
                "iso": resp.country.iso_code,
                "city": None if is_country_db else resp.city.name,
            }
        except Exception as exc:
            print(f"[-] GeoIP DB lookup failed for {ip}: {exc!r}")

    token = os.getenv("IPINFO_TOKEN")
    if token:
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": token}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country": None,
                    "iso": data.get("country"),
                    "city": data.get("city"),
                }
        except Exception as exc:
            print(f"[-] ipinfo lookup failed for {ip}: {exc!r}")

    return None


def _geo_str(geo: dict[str, str | None]) -> str:
    parts = [p for p in (geo.get("country"), f"({geo['iso']})" if geo.get("iso") else None) if p]
    location = " ".join(parts) or "unknown country"
    return f"{location}, {geo['city']}" if geo.get("city") else location


# ---------------------------------------------------------------------------
# Customer Enrichment API
# ---------------------------------------------------------------------------
def resolve_customer_ref(
    console: str, client: str | None, raw_list: list[dict[str, Any]]
) -> str | None:
    """Resolve the customer code via CUSTOMER_MAP or leading digits in the client/site name."""
    site_name = site_id = None
    if console != "Cortex XDR":
        meta = ((raw_list[0].get("resources") or [{}])[0].get("s1_metadata")) or {}
        site_name, site_id = meta.get("site_name"), meta.get("site_id")

    try:
        mapping = json.loads(os.getenv("CUSTOMER_MAP", "{}"))
    except json.JSONDecodeError:
        mapping = {}

    for key in (client, site_name, str(site_id) if site_id else None):
        if key and key in mapping:
            return str(mapping[key])

    source = client if console == "Cortex XDR" else site_name
    match = re.match(r"\s*(\d+)", source or "")
    if match:
        return match.group(1)

    # Fallback: match the first 5+ digit sequence anywhere in the identifier.
    match = re.search(r"\d{5,}", source or "")
    return match.group(0) if match else None


def fetch_customer(customer_ref: str) -> dict[str, Any]:
    """Fetch customer notes and service windows from the enrichment API."""
    url = os.getenv("ENRICH_URL", "https://enrich.cyberlys.net/colibri_api.php?action=customer")
    headers = json.loads(os.getenv("ENRICH_HEADERS", "{}"))
    token = os.getenv("ENRICH_TOKEN")
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")

    template = os.getenv("ENRICH_BODY_TEMPLATE", '{"customer_code": "{customer}"}')
    body = json.loads(template.replace("{customer}", str(customer_ref)))

    resp = requests.post(url, headers=headers, json=body, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"enrich API HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"enrich API returned ok=false: {str(data)[:200]}")
    return data


# ---------------------------------------------------------------------------
# Note Filtering and Pseudonymization
# ---------------------------------------------------------------------------
def _parse_dt(value: Any) -> datetime | None:
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _line_matches_user(line: str, idents: dict[str, Any]) -> bool:
    low = line.lower()
    for email in EMAIL_RE.findall(line):
        if email.lower() in idents["emails"] or _local(email) in idents["locals"]:
            return True
    return any(len(loc) >= 4 and loc in low for loc in idents["locals"])


def _pseudonym(token: str, idents: dict[str, Any], sanitizer: AdvancedTelemetrySanitizer) -> str:
    """Return the exact USER pseudonym assigned to the matching alert identity."""
    local = _local(token)
    for name in idents["names"]:
        if _local(name) == local:
            return sanitizer._get_hash(name, "USER")
    return sanitizer._get_hash(token, "USER")


def _sanitize_line(line: str, idents: dict[str, Any], sanitizer: AdvancedTelemetrySanitizer) -> str:
    # Replace matched alert identities longest-first so full emails precede bare usernames.
    tokens = {
        e
        for e in EMAIL_RE.findall(line)
        if e.lower() in idents["emails"] or _local(e) in idents["locals"]
    }
    tokens |= {loc for loc in idents["locals"] if len(loc) >= 4}
    for token in sorted(tokens, key=len, reverse=True):
        line = re.sub(re.escape(token), _pseudonym(token, idents, sanitizer), line, flags=re.I)

    # Pseudonymize any remaining unrelated email addresses.
    return EMAIL_RE.sub(lambda m: sanitizer._get_hash(m.group(0), "USER"), line)


def relevant_notes(
    customer: dict[str, Any],
    idents: dict[str, Any],
    sanitizer: AdvancedTelemetrySanitizer,
    now: datetime | None = None,
) -> tuple[list[str], list[str], int]:
    """Filter active notes into (user_specific, general, expired_count), dropping notes for other users."""
    now = now or datetime.now()
    user_lines: list[str] = []
    general_lines: list[str] = []
    expired = 0

    for note in customer.get("notes") or []:
        expires = _parse_dt(note.get("expires_at"))
        if expires and expires < now:
            expired += 1
            continue

        stamp = (note.get("created_at") or "")[:10]
        suffix = f" (valid until {note['expires_at']})" if note.get("expires_at") else ""
        for raw_line in str(note.get("body") or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            has_email = bool(EMAIL_RE.search(line))
            matches = _line_matches_user(line, idents)
            if has_email and not matches:
                continue

            formatted = f"- [{stamp}] {_sanitize_line(line, idents, sanitizer)}{suffix}"
            (user_lines if matches else general_lines).append(formatted)

    return user_lines, general_lines, expired


def _home_countries() -> set[str]:
    raw = os.getenv("HOME_COUNTRIES", "IT,ITALY,ITALIA")
    return {c.strip().upper() for c in raw.split(",") if c.strip()}


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------
def build_auth_context(
    console: str,
    client: str | None,
    raw: dict[str, Any] | list[dict[str, Any]],
    sanitizer: AdvancedTelemetrySanitizer | None = None,
) -> tuple[str, dict[str, Any]]:
    """Assemble the CUSTOMER CONTEXT prompt block and verification metadata for an auth alert.

    Never raises; sets `meta["verifiable"] = False` whenever geolocation is missing or a
    non-home login lacks a matching customer note so the caller routes it to manual review.
    """
    sanitizer = sanitizer or AdvancedTelemetrySanitizer()
    raw_list = _as_list(raw)
    home = _home_countries()
    lines = ["--- CUSTOMER CONTEXT (AUTHENTICATION, SANITIZED) ---"]

    idents = alert_identities(console, raw_list)
    pseudo = sanitizer._get_hash(idents["names"][0], "USER") if idents["names"] else None
    lines.append(f"Alert user: {pseudo or 'unknown'}")

    # IP geolocation
    ips = public_ips(raw_list)
    alert_ctry = alert_countries(raw_list)
    countries = {c.upper() for c in alert_ctry}
    geo_ok = bool(alert_ctry)

    if ips:
        lines.append("Source IP geolocation (GeoIP database):")
        for ip in ips:
            geo = geo_lookup(ip)
            if geo:
                geo_ok = True
                countries |= {str(v).upper() for v in (geo.get("iso"), geo.get("country")) if v}
            lines.append(f"  - {ip}: {_geo_str(geo) if geo else 'geolocation NOT available'}")
    else:
        lines.append("No public IP found in the alert.")

    if alert_ctry:
        lines.append(f"Country fields present in the alert itself: {', '.join(alert_ctry)}")
    lines.append(
        f"Customer home countries (a login from there needs no note): {', '.join(sorted(home))}"
    )

    # Customer notes and service windows
    user_lines: list[str] = []
    notes_failed = False
    try:
        ref = resolve_customer_ref(console, client, raw_list)
        if not ref:
            raise RuntimeError("customer not identified (set CUSTOMER_MAP in .env)")
        customer = fetch_customer(ref)
        user_lines, general_lines, expired = relevant_notes(customer, idents, sanitizer)

        lines.append("Customer notes about this user:")
        lines.extend(user_lines or ["  (no customer note mentions this user)"])
        if general_lines:
            lines.append("General customer notes:")
            lines.extend(general_lines)
        if expired:
            lines.append(f"({expired} expired note(s) ignored)")

        windows = customer.get("service_windows") or {}
        if windows:
            formatted_windows = "; ".join(f"{k}: {v}" for k, v in windows.items() if v)
            lines.append(f"Customer service windows: {formatted_windows}")
    except Exception as exc:
        print(f"[-] Customer context error: {exc!r}")
        notes_failed = True
        lines.append(f"Customer notes NOT available ({str(exc)[:150]}).")

    # Verification check
    home_ok = bool(countries & home)
    missing: list[str] = []
    if not geo_ok:
        missing.append("the country of the source IP could not be determined")
    if notes_failed:
        missing.append("the customer notes could not be retrieved")
    elif geo_ok and not home_ok and not user_lines:
        missing.append("the login is not from a home country and no customer note covers this user")

    verifiable = not missing
    if not verifiable:
        lines.append(f"VERIFICATION: NOT POSSIBLE ({'; '.join(missing)}).")
    lines.append(RULES_TEXT)

    text = "\n".join(lines) + "\n"
    print(text)
    return text, {
        "verifiable": verifiable,
        "missing": missing,
        "geo_ok": geo_ok,
        "home_ok": home_ok,
    }