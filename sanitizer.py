"""Deterministic HMAC-SHA256 telemetry pseudonymizer.

Walks nested Python structures (dict/list/str) directly so JSON escaping and timestamps
remain intact, producing consistent pseudonyms (e.g., HOST-xxxx) across alerts when
initialized with the same secret salt.

Supported redactions:
- Known entities harvested from ECS fields (host, user, domain, private IP)
- Extra per-alert terms (customer, site, group) and permanent blocklists (SANITIZER_BLOCKLIST)
- Emails, UNC shares (\\\\server\\share), profile directories (C:\\Users\\name, /home/name),
  MAC addresses, and validated IPv4/IPv6 addresses (public, loopback, and unspecified IPs
  remain unmasked by default)

Note: Free-form customer names in command lines are only masked if registered via
`extra_terms` or `blocklist`. Keep the salt and any exported mapping files out of git.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
from typing import Any

from dotenv import load_dotenv

load_dotenv()

# Built-in OS/service identifiers that carry diagnostic value and should not be masked.
ALLOW = {
    "system",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "root",
    "administrator",
    "nt authority",
    "nt service",
    "workgroup",
    "window manager",
    "localhost",
    "localsystem",
    "unknown",
    "none",
    "n/a",
    "public",
    "default",
    "default user",
    "all users",
    "defaultuser0",
    "windows",
    "users",
    "guest",
}

PSEUDONYM = re.compile(r"^(HOST|USER|DOMAIN|ORG|SITE|GROUP|EMAIL|PROFILE|UNC|IP|MAC)-[0-9a-f]{6,}$")
ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
HEX_ONLY = re.compile(r"^[0-9a-fA-F]{32,64}$")

EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f:]{3,}(?![\w:])")
UNC_RE = re.compile(r"(?<![\w:\\.])\\\\([A-Za-z0-9_.\-]+)(?=\\)")
PROFILE_RE = re.compile(
    r"(?<![A-Za-z0-9])((?:Users\\{1,2}|/Users/|/home/))([^\\/\s\"'<>|:*?]+)",
    re.IGNORECASE,
)
UNC_SKIP = {".", "?", "localhost", "users", "windows", "programdata"}


class AdvancedTelemetrySanitizer:
    """Pseudonymize sensitive telemetry fields consistently using salted HMAC-SHA256."""

    def __init__(
        self,
        salt: str | None = None,
        blocklist: list[str] | None = None,
        keep_public_ips: bool = True,
        hash_len: int = 10,
    ) -> None:
        salt = salt or os.getenv("SALT_PASSWORD")
        if not salt:
            raise ValueError(
                "SALT_PASSWORD is not set: without a secret salt, pseudonyms can be reversed "
                "via a hostname dictionary attack. Set SALT_PASSWORD in .env."
            )
        self._key = salt.encode()
        self.keep_public_ips = keep_public_ips
        self.hash_len = hash_len
        self.mapping_table: dict[str, str] = {}  # lowercase original -> pseudonym
        self._display: dict[str, str] = {}       # lowercase original -> original casing
        self._rx: re.Pattern[str] | None = None
        self._rx_size = -1

        env_terms = [t.strip() for t in os.getenv("SANITIZER_BLOCKLIST", "").split(",") if t.strip()]
        for term in [*(blocklist or []), *env_terms]:
            self._get_hash(term, "ORG")

    # ------------------------------------------------------------------
    # Pseudonym Generation
    # ------------------------------------------------------------------
    def _bypass_ip(self, val: str) -> bool:
        try:
            ip = ipaddress.ip_address(val)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return True
        return self.keep_public_ips and not ip.is_private

    def _get_hash(self, value: Any, prefix: str) -> Any:
        """Return (and cache) a deterministic pseudonym for `value`."""
        if value is None:
            return value
        val = str(value)
        if len(val) < 3 or val.lower() in ALLOW or PSEUDONYM.match(val):
            return val
        if prefix == "IP" and self._bypass_ip(val):
            return val

        key = val.lower()
        if key not in self.mapping_table:
            digest = hmac.new(self._key, key.encode(), hashlib.sha256).hexdigest()[: self.hash_len]
            self.mapping_table[key] = f"{prefix.upper()}-{digest}"
            self._display[key] = val
        return self.mapping_table[key]

    def register(self, terms: dict[str, str] | None) -> None:
        """Register additional {term: prefix} pairs to redact wherever they appear."""
        for term, prefix in (terms or {}).items():
            self._get_hash(term, prefix)

    # ------------------------------------------------------------------
    # Entity Harvesting
    # ------------------------------------------------------------------
    def _harvest_entities(self, data: Any) -> None:
        if isinstance(data, dict):
            host = data.get("host")
            if isinstance(host, dict):
                name = host.get("name")
                if name:
                    self._get_hash(name, "HOST")
                    # Also register the short hostname when an FQDN is given.
                    if "." in str(name) and not re.fullmatch(r"[\d.]+", str(name)):
                        self._get_hash(str(name).split(".")[0], "HOST")
                if host.get("domain"):
                    self._get_hash(host["domain"], "DOMAIN")
                if host.get("ip"):
                    self._get_hash(host["ip"], "IP")

            user = data.get("user")
            if isinstance(user, dict):
                uname, udom = user.get("name"), user.get("domain")
                if uname and "\\" in str(uname):
                    udom, uname = str(uname).split("\\", 1)
                if uname:
                    self._get_hash(uname, "USER")
                if udom:
                    self._get_hash(udom, "DOMAIN")

            for val in data.values():
                if isinstance(val, (dict, list)):
                    self._harvest_entities(val)
        elif isinstance(data, list):
            for item in data:
                self._harvest_entities(item)

    # ------------------------------------------------------------------
    # Text Redaction
    # ------------------------------------------------------------------
    def _entity_regex(self) -> re.Pattern[str] | None:
        keys = [k for k in self.mapping_table if not self._is_ip(k)]
        if len(keys) != self._rx_size:
            keys.sort(key=len, reverse=True)
            if keys:
                pattern = r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(k) for k in keys) + r")(?![A-Za-z0-9])"
                self._rx = re.compile(pattern, re.IGNORECASE)
            else:
                self._rx = None
            self._rx_size = len(keys)
        return self._rx

    @staticmethod
    def _is_ip(val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def sanitize_text(self, text: Any) -> Any:
        """Redact sensitive identifiers within a single string (paths, command lines, descriptions)."""
        if not isinstance(text, str) or not text or ISO_TS.match(text) or HEX_ONLY.match(text):
            return text

        text = EMAIL_RE.sub(lambda m: self._get_hash(m.group(0), "EMAIL"), text)

        rx = self._entity_regex()
        if rx:
            text = rx.sub(lambda m: self.mapping_table[m.group(0).lower()], text)

        text = UNC_RE.sub(
            lambda m: "\\\\"
            + (
                m.group(1)
                if m.group(1).lower() in UNC_SKIP or PSEUDONYM.match(m.group(1))
                else self._get_hash(m.group(1), "UNC")
            ),
            text,
        )
        text = PROFILE_RE.sub(
            lambda m: m.group(1)
            + (
                m.group(2)
                if m.group(2).startswith(("%", "$")) or PSEUDONYM.match(m.group(2))
                else self._get_hash(m.group(2), "PROFILE")
            ),
            text,
        )
        text = MAC_RE.sub(lambda m: self._get_hash(m.group(0), "MAC"), text)
        text = IPV4_RE.sub(lambda m: self._get_hash(m.group(0), "IP"), text)

        def replace_ipv6(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if ":" not in candidate:
                return candidate
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                return candidate  # Ignore timestamps or colon-delimited hex strings.
            return self._get_hash(candidate, "IP")

        return IPV6_RE.sub(replace_ipv6, text)

    def _walk(self, data: Any, key: str | None = None) -> Any:
        if isinstance(data, dict):
            return {k: self._walk(v, k) for k, v in data.items()}
        if isinstance(data, list):
            return [self._walk(v, key) for v in data]
        if isinstance(data, str) and key != "@timestamp":
            return self.sanitize_text(data)
        return data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def sanitize_log(
        self, log_entry: dict[str, Any], extra_terms: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Sanitize an ECS dictionary, optionally registering `<Normalizer>.sensitive_terms(raw)`."""
        self.register(extra_terms)
        self._harvest_entities(log_entry)
        return self._walk(log_entry)

    def export_mapping(self, path: str) -> None:
        """Write `{pseudonym: original_value}` to disk for offline analyst lookup. Sensitive file."""
        reverse_map = {self.mapping_table[k]: self._display[k] for k in self.mapping_table}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(reverse_map, f, indent=1, ensure_ascii=False)