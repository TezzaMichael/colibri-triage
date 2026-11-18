"""ECS normalizers for SentinelOne and Cortex XDR alerts and telemetry.

Output schema (empty/null fields are stripped recursively):
    @timestamp (ISO 8601 UTC), event{id,kind,provider,severity,rule_name,rule_type,...},
    host{name,domain,ip,os,type}, user{name,domain},
    process{name,pid,command_line,executable,hash,signed,parent{...,parent{...}}},
    file{}, registry{}, network{}, threat{description,mitre_tactics,mitre_techniques}

Process lineage (`process -> parent -> parent.parent`) always maps:
    target process -> actor process -> ancestor (parent / causality actor).

Intentionally excluded fields (leak analyst outcomes/handling):
    status, state, verdict_*, assignee, note, resolution/resolve_comment, last_updated.

Each normalizer also implements `sensitive_terms(raw)` to extract discarded metadata
(customer, site, domain, user) that may still appear inside paths or command lines,
so the caller can pass them to `sanitize_log(..., extra_terms=...)`.
"""

import ast
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

SKIP_DOMAINS = {"NT AUTHORITY", "NT SERVICE", "WORKGROUP", "WINDOW MANAGER", "FONT DRIVER HOST"}
SEVERITY_OCSF = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "fatal"}
SEV_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "unknown": 0,
}
HASH_ALGO = {1: "md5", 2: "sha1", 3: "sha256"}


# ---------------------------------------------------------------------------
# Common Helpers
# ---------------------------------------------------------------------------
def iso_time(value: Any) -> str | None:
    """Convert epoch seconds/milliseconds (int, float, or numeric str) to ISO 8601 UTC."""
    if value in (None, ""):
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return value
    if num > 1e11:  # Epoch milliseconds.
        num /= 1000.0
    return datetime.fromtimestamp(num, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def clean(data: Any) -> Any:
    """Recursively strip None, empty strings, empty dicts, and empty lists."""
    if isinstance(data, dict):
        cleaned = {k: clean(v) for k, v in data.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, "", {}, [])}
    if isinstance(data, list):
        return [item for item in (clean(i) for i in data) if item not in (None, "", {}, [])]
    return data


def split_user(raw: str | None) -> tuple[str | None, str | None]:
    """Split 'DOMAIN\\user' into (domain, user), dropping built-in Windows service domains."""
    if not raw:
        return None, None
    if "\\" in raw:
        domain, user = raw.split("\\", 1)
        return (None if domain.upper() in SKIP_DOMAINS else domain), user
    return None, raw


def norm_severity(sev: Any) -> str | None:
    if sev is None or sev == "":
        return None
    if isinstance(sev, int):
        return SEVERITY_OCSF.get(sev, str(sev))
    return re.sub(r"^SEV_\d+_", "", str(sev)).lower()


def chain(*procs: dict[str, Any]) -> dict[str, Any]:
    """Nest process dicts ordered [target, actor, ancestor, ...] into process.parent chains."""
    cleaned = [clean(p) for p in procs if clean(p)]
    if not cleaned:
        return {}
    for child, parent in zip(cleaned, cleaned[1:]):
        child["parent"] = parent
    return cleaned[0]


def _first(*values: Any) -> Any:
    for val in values:
        if val not in (None, "", {}, []):
            return val
    return None


def _terms(**groups: list[str | None]) -> dict[str, str]:
    """Build {term: ENTITY_PREFIX} excluding values shorter than 3 characters."""
    out: dict[str, str] = {}
    for prefix, values in groups.items():
        for val in values:
            if val and len(str(val)) >= 3:
                out[str(val)] = prefix.upper()
    return out


# ---------------------------------------------------------------------------
# SentinelOne
# ---------------------------------------------------------------------------
class SentinelOneToECSNormalizer:
    """Normalize native SentinelOne OCSF alerts into ECS."""

    _COVERED_OBS = re.compile(r"^(src\.|agent\.|tgt\.process\.(name|pid)$)")

    @staticmethod
    def _proc(proc: dict[str, Any] | None) -> dict[str, Any]:
        proc = proc or {}
        file_info = proc.get("file") or {}
        user = proc.get("user") or {}
        hashes = {
            HASH_ALGO[h["algorithm_id"]]: h.get("value")
            for h in (file_info.get("hashes") or [])
            if h.get("algorithm_id") in HASH_ALGO
        }
        return {
            "name": _first(proc.get("name"), file_info.get("name")),
            "pid": proc.get("pid"),
            "command_line": proc.get("cmd_line"),
            "executable": file_info.get("path"),
            "hash": hashes,
            "signed": (proc.get("xattributes") or {}).get("signed_status"),
            "_user": _first(
                (user.get("account") or {}).get("name"),
                user.get("name"),
                user.get("uid"),
            ),
        }

    def normalize(self, alert: dict[str, Any]) -> dict[str, Any]:
        fi = alert.get("finding_info") or {}
        res = (alert.get("resources") or [{}])[0] or {}
        ev = (alert.get("evidences") or [{}])[0] or {}
        actor = (ev.get("actor") or {}).get("process") or {}

        target = self._proc(ev.get("process"))
        src = self._proc(actor)
        ancestor = self._proc(actor.get("parent_process"))

        raw_user = _first(
            target.pop("_user"),
            src.pop("_user"),
            ancestor.pop("_user"),
            ((alert.get("device") or {}).get("owner") or {}).get("name"),
        )
        udom, uname = split_user(raw_user)

        tactics: set[str] = set()
        techniques: set[str] = set()
        extra_obs: dict[str, str] = {}

        for rel in fi.get("related_events") or []:
            for atk in rel.get("attacks") or []:
                if (atk.get("tactic") or {}).get("name"):
                    tactics.add(atk["tactic"]["name"])
                if (atk.get("technique") or {}).get("uid"):
                    techniques.add(atk["technique"]["uid"])
            # Keep observables not already mapped to top-level ECS fields.
            for ob in rel.get("observables") or []:
                name, val = ob.get("name") or "", ob.get("value")
                if name and val and not self._COVERED_OBS.match(name):
                    extra_obs[name] = str(val)[:300]

        dst = ev.get("dst_endpoint") or {}
        net = {
            "destination": {
                "ip": dst.get("ip"),
                "port": dst.get("port"),
                "domain": _first(dst.get("hostname"), dst.get("name")),
            }
        }
        url = (ev.get("url") or {}).get("url_string")

        return clean(
            {
                "@timestamp": iso_time(_first(alert.get("time"), fi.get("first_seen_time"))),
                "event": {
                    "id": str(_first(fi.get("internal_uid"), alert.get("uid"))),
                    "kind": "alert",
                    "provider": "SentinelOne",
                    "severity": norm_severity(alert.get("severity_id")),
                    "rule_name": fi.get("title"),
                    "rule_type": (fi.get("analytic") or {}).get("category"),
                },
                "host": {
                    "name": _first(res.get("name"), (alert.get("device") or {}).get("name")),
                    "type": res.get("type"),
                    "ip": (ev.get("src_endpoint") or {}).get("ip"),
                    "os": {"name": ((ev.get("device") or {}).get("os") or {}).get("name")},
                },
                "user": {"name": uname, "domain": udom},
                "process": chain(target, src, ancestor),
                "network": {**net, "url": url},
                "threat": {
                    "description": fi.get("desc"),
                    "mitre_tactics": sorted(tactics),
                    "mitre_techniques": sorted(techniques),
                },
                "observables": extra_obs,
            }
        )

    @staticmethod
    def sensitive_terms(alert: dict[str, Any]) -> dict[str, str]:
        res = (alert.get("resources") or [{}])[0] or {}
        meta = res.get("s1_metadata") or alert.get("s1_detection_metadata") or {}
        acct = meta.get("account_name") or ""
        stripped = re.sub(r"^\s*\d{4,}\s*-\s*", "", acct)

        ev = (alert.get("evidences") or [{}])[0] or {}
        users: list[str | None] = []
        domains: list[str | None] = []
        for proc in ((ev.get("actor") or {}).get("process") or {}, ev.get("process") or {}):
            dom, usr = split_user(SentinelOneToECSNormalizer._proc(proc)["_user"])
            users.append(usr)
            domains.append(dom)

        owner = ((alert.get("device") or {}).get("owner") or {}).get("name")
        return _terms(
            org=[acct, stripped, *re.split(r"\W+", stripped)],
            site=[meta.get("site_name")],
            group=[meta.get("group_name")],
            domain=domains,
            user=[*users, owner],
        )


class SentinelOneDVToECSNormalizer:
    """Normalize SentinelOne Deep Visibility telemetry events into ECS."""

    @staticmethod
    def _proc(
        ev: dict[str, Any],
        prefix: str,
        legacy_name: str | None = None,
        legacy_cmd: str | None = None,
    ) -> dict[str, Any]:
        return {
            "name": _first(ev.get(f"{prefix}ProcName"), ev.get(legacy_name) if legacy_name else None),
            "pid": ev.get(f"{prefix}ProcPid"),
            "command_line": _first(
                ev.get(f"{prefix}ProcCmdLine"), ev.get(legacy_cmd) if legacy_cmd else None
            ),
            "executable": ev.get(f"{prefix}ProcImagePath"),
            "hash": {
                "sha1": ev.get(f"{prefix}ProcImageSha1"),
                "sha256": ev.get(f"{prefix}ProcImageSha256"),
            },
        }

    def normalize(self, ev: dict[str, Any]) -> dict[str, Any]:
        udom, uname = split_user(_first(ev.get("srcProcUser"), ev.get("loginsUserName")))
        event_type = ev.get("eventType") or ""
        src = self._proc(ev, "src", "processName", "processCmd")
        tgt = self._proc(ev, "tgt")
        parent = {
            "name": ev.get("srcProcParentName"),
            "executable": ev.get("srcProcParentImagePath"),
        }

        has_target = bool(tgt.get("name") or tgt.get("command_line"))
        proc = (
            chain(tgt, src, parent)
            if has_target and "process" in event_type.lower()
            else chain(src, parent)
        )

        return clean(
            {
                "@timestamp": iso_time(_first(ev.get("createdAt"), ev.get("eventTime"))),
                "event": {"provider": "SentinelOne-DV", "action": event_type},
                "host": {"name": ev.get("endpointName"), "domain": udom},
                "user": {"name": uname},
                "process": proc,
                "file": {
                    "path": ev.get("tgtFilePath"),
                    "old_path": ev.get("tgtFileOldPath"),
                    "hash": {
                        "sha1": ev.get("tgtFileSha1"),
                        "sha256": ev.get("tgtFileSha256"),
                    },
                },
                "network": {
                    "source": {"ip": ev.get("srcIp"), "port": ev.get("srcPort")},
                    "destination": {
                        "ip": ev.get("dstIp"),
                        "port": ev.get("dstPort"),
                        "domain": ev.get("dnsRequest"),
                    },
                    "url": _first(ev.get("networkUrl"), ev.get("url")),
                },
                "registry": {"path": ev.get("registryKeyPath"), "value": ev.get("registryValue")},
            }
        )

    @staticmethod
    def sensitive_terms(ev: dict[str, Any]) -> dict[str, str]:
        dom, usr = split_user(_first(ev.get("srcProcUser"), ev.get("loginsUserName")))
        return _terms(domain=[dom], user=[usr])


# ---------------------------------------------------------------------------
# Cortex XDR
# ---------------------------------------------------------------------------
class CortexToECSNormalizer:
    """Normalize native Cortex XDR alerts into ECS."""

    @staticmethod
    def _proc(alert: dict[str, Any], prefix: str) -> dict[str, Any]:
        return {
            "name": alert.get(f"{prefix}_image_name"),
            "pid": alert.get(f"{prefix}_os_pid"),
            "command_line": _first(
                alert.get(f"{prefix}_command_line"),
                alert.get(f"{prefix}_image_command_line"),
            ),
            "executable": alert.get(f"{prefix}_image_path"),
            "hash": {"sha256": alert.get(f"{prefix}_image_sha256")},
            "signed": alert.get(f"{prefix}_signature_status"),
            "publisher": alert.get(f"{prefix}_signature_vendor"),
        }

    def normalize(self, alert: dict[str, Any]) -> dict[str, Any]:
        ips = alert.get("host_ip")
        if isinstance(ips, list):
            ip = ips[0] if ips else None
        elif ips:
            ip = str(ips).split(",")[0].strip()
        else:
            ip = None

        dom_u, uname = split_user(alert.get("user_name"))
        domain = _first(alert.get("agent_device_domain"), dom_u)

        tgt = self._proc(alert, "action_process")
        actor = self._proc(alert, "actor_process")
        causality = self._proc(alert, "causality_actor_process")
        # Avoid duplicating identical target and actor entries in the process chain.
        if tgt.get("name") == actor.get("name") and tgt.get("command_line") == actor.get("command_line"):
            tgt = {}

        tactic = alert.get("mitre_tactic_id_and_name")
        tech = alert.get("mitre_technique_id_and_name")

        def as_list(val: Any) -> list[Any]:
            return [x for x in (val if isinstance(val, list) else [val]) if x]

        return clean(
            {
                "@timestamp": iso_time(alert.get("detection_timestamp")),
                "event": {
                    "id": str(alert.get("alert_id")) if alert.get("alert_id") is not None else None,
                    "kind": "alert",
                    "provider": "CortexXDR",
                    "severity": norm_severity(alert.get("severity")),
                    "rule_name": alert.get("name"),
                    "rule_type": alert.get("source"),
                    "category": alert.get("category"),
                    "action": alert.get("action_pretty"),
                },
                "host": {
                    "name": alert.get("host_name"),
                    "domain": domain,
                    "ip": ip,
                    "os": {
                        "name": alert.get("agent_os_type"),
                        "version": alert.get("agent_os_sub_type"),
                    },
                },
                "user": {"name": uname, "domain": dom_u},
                "process": chain(tgt, actor, causality),
                "file": {
                    "name": alert.get("action_file_name"),
                    "path": alert.get("action_file_path"),
                    "hash": {
                        "sha256": alert.get("action_file_sha256"),
                        "md5": alert.get("action_file_md5"),
                    },
                },
                "registry": {
                    "path": alert.get("action_registry_key_name"),
                    "value": alert.get("action_registry_value_name"),
                    "data": alert.get("action_registry_data"),
                },
                "network": {
                    "source": {
                        "ip": alert.get("action_local_ip"),
                        "port": alert.get("action_local_port"),
                    },
                    "destination": {
                        "ip": alert.get("action_remote_ip"),
                        "port": alert.get("action_remote_port"),
                        "domain": alert.get("action_external_hostname"),
                    },
                },
                "threat": {
                    "description": alert.get("description"),
                    "mitre_tactics": as_list(tactic),
                    "mitre_techniques": as_list(tech),
                },
            }
        )

    @staticmethod
    def sensitive_terms(alert: dict[str, Any]) -> dict[str, str]:
        dom_u, uname = split_user(alert.get("user_name"))
        fqdn = alert.get("agent_fqdn") or ""
        suffix = fqdn.split(".", 1)[1] if "." in fqdn else None
        return _terms(
            domain=[alert.get("agent_device_domain"), dom_u, suffix],
            user=[uname],
            host=[alert.get("host_name")],
        )


class CortexXQLToECSNormalizer:
    """Normalize Cortex XDR XQL (`xdr_data`) telemetry events into ECS."""

    @staticmethod
    def _proc(ev: dict[str, Any], prefix: str) -> dict[str, Any]:
        return {
            "name": ev.get(f"{prefix}_image_name"),
            "pid": ev.get(f"{prefix}_os_pid"),
            "command_line": _first(
                ev.get(f"{prefix}_command_line"),
                ev.get(f"{prefix}_image_command_line"),
            ),
            "executable": ev.get(f"{prefix}_image_path"),
            "hash": {"sha256": ev.get(f"{prefix}_image_sha256")},
        }

    def normalize(self, ev: dict[str, Any]) -> dict[str, Any]:
        udom, uname = split_user(
            _first(ev.get("actor_effective_username"), ev.get("action_process_username"))
        )
        event_type = ev.get("event_type") or ""
        actor = self._proc(ev, "actor_process")
        causality = self._proc(ev, "causality_actor_process")
        tgt = self._proc(ev, "action_process")

        is_proc = event_type.upper() == "PROCESS" and bool(
            tgt.get("name") or tgt.get("command_line")
        )

        return clean(
            {
                "@timestamp": iso_time(_first(ev.get("_time"), ev.get("event_timestamp"))),
                "event": {
                    "provider": "CortexXDR-XQL",
                    "action": event_type,
                    "type": [ev.get("event_sub_type")] if ev.get("event_sub_type") else None,
                },
                "host": {"name": ev.get("agent_hostname"), "domain": udom},
                "user": {"name": uname},
                "process": chain(tgt, actor, causality) if is_proc else chain(actor, causality),
                "file": {
                    "path": ev.get("action_file_path"),
                    "name": ev.get("action_file_name"),
                    "hash": {
                        "sha256": _first(
                            ev.get("action_file_sha256"),
                            ev.get("actor_process_image_sha256"),
                        )
                    },
                },
                "network": {
                    "source": {
                        "ip": ev.get("action_local_ip"),
                        "port": ev.get("action_local_port"),
                    },
                    "destination": {
                        "ip": ev.get("action_remote_ip"),
                        "port": ev.get("action_remote_port"),
                        "domain": _first(
                            ev.get("dns_query_name"),
                            ev.get("action_external_hostname"),
                        ),
                    },
                },
                "registry": {
                    "path": ev.get("action_registry_key_name"),
                    "value": ev.get("action_registry_value_name"),
                    "data": ev.get("action_registry_data"),
                },
            }
        )

    @staticmethod
    def sensitive_terms(ev: dict[str, Any]) -> dict[str, str]:
        dom, usr = split_user(ev.get("actor_effective_username"))
        return _terms(domain=[dom], user=[usr], host=[ev.get("agent_hostname")])


class CortexCaseToECSNormalizer:
    """Normalize a Cortex XDR incident/case (with optional associated alerts) into a single payload.

    When `alerts` is provided, alerts are normalized, deduplicated by `(rule_name, host, command_line)`
    with occurrence counts, and capped to the `max_alerts` highest-severity entries to stay within
    the LLM context budget.
    """

    def __init__(self, max_alerts: int = 10) -> None:
        self.max_alerts = max_alerts
        self._alert_norm = CortexToECSNormalizer()

    @staticmethod
    def _pylist(value: Any) -> list[str]:
        if isinstance(value, list):
            return value
        if not value:
            return []
        try:
            parsed = ast.literal_eval(value)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, SyntaxError):
            return [str(value)]

    def normalize(
        self, case: dict[str, Any], alerts: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        def pick(*keys: str) -> Any:
            return _first(*(case.get(k) for k in keys))

        issue_fields = (
            ("critical", "Critical Severity Issues"),
            ("high", "High Severity Issues"),
            ("medium", "Medium Severity Issues"),
            ("low", "Low Severity Issues"),
        )
        out: dict[str, Any] = {
            "case": {
                "id": str(pick("Case ID", "incident_id", "case_id")),
                "name": pick("Case Name", "incident_name", "case_name"),
                "description": pick("Case Description", "description"),
                "severity": norm_severity(pick("Severity", "severity")),
                "score": pick("Score", "score"),
                "issue_counts": {
                    label: int(case[col])
                    for label, col in issue_fields
                    if str(case.get(col, "")).strip().isdigit()
                },
                "mitre_tactics": self._pylist(
                    pick("MITRE ATT&CK Tactic", "mitre_tactics_ids_and_names")
                ),
                "mitre_techniques": self._pylist(
                    pick("MITRE ATT&CK Technique", "mitre_techniques_ids_and_names")
                ),
            }
        }

        if alerts:
            normed = [self._alert_norm.normalize(a) for a in alerts]
            groups: dict[tuple[Any, ...], dict[str, Any]] = {}
            for item in normed:
                key = (
                    item.get("event", {}).get("rule_name"),
                    item.get("host", {}).get("name"),
                    item.get("process", {}).get("command_line"),
                )
                if key in groups:
                    groups[key]["count"] += 1
                else:
                    groups[key] = {**item, "count": 1}

            ranked = sorted(
                groups.values(),
                key=lambda item: -SEV_ORDER.get(
                    item.get("event", {}).get("severity", "unknown"), 0
                ),
            )
            out["alerts"] = ranked[: self.max_alerts]
            out["alerts_summary"] = {
                "total": len(normed),
                "distinct": len(groups),
                "shown": len(out["alerts"]),
                "rules": dict(
                    Counter(
                        item.get("event", {}).get("rule_name") for item in normed
                    ).most_common(10)
                ),
            }

        return clean(out)

    @staticmethod
    def sensitive_terms(
        case: dict[str, Any], alerts: list[dict[str, Any]] | None = None
    ) -> dict[str, str]:
        terms: dict[str, str] = {}
        for alert in alerts or []:
            terms.update(CortexToECSNormalizer.sensitive_terms(alert))
        return terms


# ---------------------------------------------------------------------------
# Telemetry Context Window Builder
# ---------------------------------------------------------------------------
def build_context_window(
    alert_ecs: dict[str, Any],
    events_ecs: list[dict[str, Any]],
    max_events: int = 60,
    window: str = "+-1h",
) -> dict[str, Any]:
    """Bundle a normalized alert with deduplicated, chronologically sorted telemetry events."""

    def signature(ev: dict[str, Any]) -> tuple[Any, ...]:
        return (
            ev.get("event", {}).get("action"),
            ev.get("host", {}).get("name"),
            ev.get("process", {}).get("command_line"),
            ev.get("process", {}).get("name"),
            ev.get("file", {}).get("path"),
            ev.get("network", {}).get("destination", {}).get("ip"),
            ev.get("network", {}).get("destination", {}).get("domain"),
            ev.get("registry", {}).get("path"),
        )

    ordered = sorted(events_ecs, key=lambda ev: ev.get("@timestamp") or "")
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for ev in ordered:
        sig = signature(ev)
        if sig in merged:
            merged[sig]["count"] += 1
            merged[sig]["last_seen"] = ev.get("@timestamp")
        else:
            merged[sig] = {**ev, "count": 1, "last_seen": ev.get("@timestamp")}

    compact = list(merged.values())
    shown = compact[:max_events]
    return clean(
        {
            "alert": alert_ecs,
            "context_events": shown,
            "context_summary": {
                "window": window,
                "total_events": len(events_ecs),
                "distinct_events": len(compact),
                "shown": len(shown),
                "truncated": len(compact) > max_events,
            },
        }
    )