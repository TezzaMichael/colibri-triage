"""Alert and telemetry ingestion from SentinelOne (GraphQL / Deep Visibility) and Cortex XDR (REST / XQL)."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from dotenv import load_dotenv

from api import cortexApi, s1Api
from normalizer import (
    CortexToECSNormalizer,
    CortexXQLToECSNormalizer,
    SentinelOneDVToECSNormalizer,
    SentinelOneToECSNormalizer,
)
from sanitizer import AdvancedTelemetrySanitizer

load_dotenv()


# ---------------------------------------------------------------------------
# SentinelOne: Alert Retrieval & Deep Visibility Telemetry
# ---------------------------------------------------------------------------
def get_alert_s1(target_uuid: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Fetch a SentinelOne unified alert by ID, normalize it to ECS, and sanitize sensitive fields."""
    print("Fetching specific alert from SentinelOne (GraphQL)...")
    endpoint = f"{os.getenv('URL_S1')}/unifiedalerts/graphql"
    headers = {
        "Authorization": f"ApiToken {s1Api()}",
        "Content-Type": "application/json",
    }
    payload = {
        "query": """
            query GetRawData($alertId: ID!) {
                alert(id: $alertId) {
                    rawData
                }
            }
        """,
        "variables": {"alertId": target_uuid},
    }

    response = requests.post(endpoint, headers=headers, json=payload)
    if response.status_code != 200:
        print(f"HTTP Error: {response.text}")
        return None

    data = response.json().get("data", {}).get("alert", {}).get("rawData")
    if isinstance(data, str):
        try:
            raw_alert = json.loads(data)
        except json.JSONDecodeError:
            print("Error parsing rawData JSON.")
            return None
    else:
        raw_alert = data

    if not raw_alert:
        print("No raw data found.")
        return None

    normalizer = SentinelOneToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()

    normalized_alert = normalizer.normalize(raw_alert)
    sanitized = sanitizer.sanitize_log(normalized_alert)

    filename = "test/test_alert_S1_unified.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)

    print(f"[+] Alert normalized, anonymized, and successfully saved to: {filename}")
    return sanitized, raw_alert


def _parse_alert_time(raw_alert: dict[str, Any]) -> datetime:
    """Parse alert timestamp (epoch seconds/ms or ISO 8601) into a UTC datetime."""
    value = (
        raw_alert.get("time")
        or raw_alert.get("start_time")
        or (raw_alert.get("finding_info") or {}).get("created_time")
    )
    if value is None:
        return datetime.now(timezone.utc)

    try:
        num = float(value)
        if num > 1e11:  # Convert epoch milliseconds to seconds.
            num /= 1000.0
        return datetime.fromtimestamp(num, tz=timezone.utc)
    except (TypeError, ValueError):
        pass

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _query_escape(value: Any) -> str:
    """Escape backslashes and double quotes for Deep Visibility / XQL string literals."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _extract_s1_context(raw_alert: dict[str, Any]) -> dict[str, Any]:
    """Extract pivot indicators (host, site_id, user, file hashes, remote IPs) from raw S1 alert data."""
    ctx: dict[str, Any] = {"host": "", "site_id": None, "user": "", "hashes": set(), "ips": set()}

    resources = raw_alert.get("resources", [])
    if resources:
        ctx["host"] = resources[0].get("name", "") or ""
        ctx["site_id"] = (resources[0].get("s1_metadata") or {}).get("site_id")

    for ev in raw_alert.get("evidences", []):
        proc = ev.get("process") or {}

        user = (
            (proc.get("user") or {}).get("name")
            or (ev.get("user") or {}).get("name")
            or (ev.get("actor") or {}).get("user", {}).get("name")
        )
        if user and not ctx["user"]:
            ctx["user"] = user

        # Collect SHA1 (2) and SHA256 (3) hashes.
        for h in (proc.get("file") or {}).get("hashes", []):
            if h.get("algorithm_id") in (2, 3) and h.get("value"):
                ctx["hashes"].add(h["value"])

        dst_ip = (ev.get("dst_endpoint") or {}).get("ip")
        if dst_ip:
            ctx["ips"].add(dst_ip)

    return ctx


def _format_telemetry_event(ev: dict[str, Any]) -> str:
    """Render a normalized ECS telemetry event into a single compact line for the LLM."""
    proc = ev.get("process", {})
    net = ev.get("network", {})
    dst = net.get("destination", {})

    parts = [
        f"[{ev.get('@timestamp', 'Unknown')}]",
        f"EVENT: {ev.get('event', {}).get('action', 'Unknown')}",
        f"HOST: {ev.get('host', {}).get('name', 'N/A')}",
        f"USER: {ev.get('user', {}).get('name', 'N/A')}",
        f"PROCESS: {proc.get('name', 'Unknown')}",
        f"CMD: {proc.get('command_line', 'N/A')}",
    ]
    if proc.get("parent", {}).get("name"):
        parts.append(f"PARENT: {proc['parent']['name']}")
    if ev.get("file", {}).get("path"):
        parts.append(f"FILE: {ev['file']['path']}")
    if dst.get("ip"):
        parts.append(f"DST: {dst['ip']}:{dst.get('port', '')}")
    if dst.get("domain"):
        parts.append(f"DNS: {dst['domain']}")
    if net.get("url"):
        parts.append(f"URL: {net['url']}")
    if ev.get("registry", {}).get("path"):
        parts.append(f"REG: {ev['registry']['path']}")

    return " | ".join(parts)


def _run_dv_query(
    base_url: str, headers: dict[str, str], payload: dict[str, Any], max_wait: int = 90
) -> list[dict[str, Any]]:
    """Submit a Deep Visibility query, poll until completion, and return the resulting events."""
    resp = requests.post(f"{base_url}/dv/init-query", headers=headers, json=payload, timeout=30)
    if resp.status_code != 200:
        print(f"[-] init-query HTTP {resp.status_code}: {resp.text}")
        return []
    query_id = resp.json()["data"]["queryId"]

    deadline = time.time() + max_wait
    while time.time() < deadline:
        status_resp = requests.get(
            f"{base_url}/dv/query-status",
            headers=headers,
            params={"queryId": query_id},
            timeout=30,
        )
        status_resp.raise_for_status()
        status = status_resp.json().get("data", {})
        state = status.get("responseState")

        if state in ("FAILED", "CANCELED", "TIMED_OUT"):
            print(f"[-] DV query ended with state {state}")
            return []
        if state == "FINISHED" or status.get("progressStatus") == 100:
            break
        time.sleep(2)
    else:
        print("[-] Timed out waiting for DV results (attempting partial fetch)")

    events_resp = requests.get(
        f"{base_url}/dv/events",
        headers=headers,
        params={"queryId": query_id, "limit": payload.get("limit", 50)},
        timeout=30,
    )
    events_resp.raise_for_status()
    return events_resp.json().get("data", [])


def get_s1_additional_logs(
    raw_alert: dict[str, Any],
    window_minutes: int = 30,
    limit: int = 50,
    sanitizer: AdvancedTelemetrySanitizer | None = None,
) -> str:
    """Query SentinelOne Deep Visibility around the alert window and return sanitized telemetry."""
    print("\n🔍 Extracting context from raw alert for Deep Visibility query...")

    base_url = os.getenv("URL_S1", "").rstrip("/")
    headers = {
        "Authorization": f"ApiToken {s1Api()}",
        "Content-Type": "application/json",
    }

    ctx = _extract_s1_context(raw_alert)
    print(
        f"   [>] Host: {ctx['host']} | Site: {ctx['site_id']} | "
        f"User: {ctx['user']} | Hashes: {len(ctx['hashes'])}"
    )

    conditions: list[str] = []
    if ctx["host"]:
        conditions.append(f'EndpointName = "{_query_escape(ctx["host"])}"')
    if ctx["user"]:
        conditions.append(f'SrcProcUser = "{_query_escape(ctx["user"])}"')
    for h in ctx["hashes"]:
        escaped = _query_escape(h)
        conditions.append(
            f'(SrcProcImageSha1 = "{escaped}" OR TgtProcImageSha1 = "{escaped}" OR TgtFileSha1 = "{escaped}")'
        )

    if not conditions:
        return "--- ADDITIONAL TELEMETRY ---\nNo contextual data available for query."

    query_str = " OR ".join(conditions)
    alert_time = _parse_alert_time(raw_alert)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"

    payload: dict[str, Any] = {
        "fromDate": (alert_time - timedelta(minutes=window_minutes)).strftime(fmt),
        "toDate": (alert_time + timedelta(minutes=window_minutes)).strftime(fmt),
        "query": query_str,
        "limit": limit,
    }
    if ctx["site_id"]:
        payload["siteIds"] = [str(ctx["site_id"])]

    print(f"   [>] Query: {query_str}")
    print(f"   [>] Window: {payload['fromDate']} -> {payload['toDate']}")

    try:
        results = _run_dv_query(base_url, headers, payload)
    except Exception as exc:
        print(f"[-] DV error: {exc!r}")
        return "--- ADDITIONAL TELEMETRY ---\nDeep Visibility query failed."

    if not results:
        return "--- ADDITIONAL TELEMETRY ---\nNo additional events found in the timeframe."

    results.sort(key=lambda ev: ev.get("createdAt") or "")

    dv_normalizer = SentinelOneDVToECSNormalizer()
    normalized = [dv_normalizer.normalize(ev) for ev in results]

    # Sanitize the entire batch together so pseudonyms stay consistent across events.
    sanitizer = sanitizer or AdvancedTelemetrySanitizer()
    sanitized = sanitizer.sanitize_log({"events": normalized})["events"]

    lines = ["--- ADDITIONAL TELEMETRY (DEEP VISIBILITY, SANITIZED) ---"]
    lines.extend(_format_telemetry_event(ev) for ev in sanitized)
    formatted = "\n".join(lines) + "\n"

    print(formatted)
    return formatted


# ---------------------------------------------------------------------------
# Cortex XDR: Incident Alerts & XQL Telemetry
# ---------------------------------------------------------------------------
def get_alert_cortex(
    case_id: str, client: str
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Fetch all alerts belonging to a Cortex XDR incident, normalize to ECS, and sanitize."""
    print(f"Fetching alert for Case ID {case_id} from Cortex XDR...")

    api_token, endpoint, auth_id = cortexApi(client)
    cortex_fqdn = endpoint.rstrip("/")

    headers = {
        "x-xdr-auth-id": str(auth_id),
        "Authorization": api_token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }

    url = f"{cortex_fqdn}/public_api/v1/incidents/get_incident_extra_data"
    payload = {"request_data": {"incident_id": str(case_id)}}

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        print(f"HTTP/Connection error to Cortex: {exc}")
        return None

    json_response = response.json()
    alerts_container = json_response.get("reply", {}).get("alerts", {})

    if isinstance(alerts_container, dict) and "data" in alerts_container:
        alerts = alerts_container["data"]
    elif isinstance(alerts_container, list):
        alerts = alerts_container
    else:
        alerts = []

    if not alerts:
        print(f"No alerts found for Case ID {case_id}.")
        return None

    print(f"[!] Found {len(alerts)} REAL alert(s) associated with Case ID {case_id}.")

    normalizer = CortexToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    processed_alerts: list[dict[str, Any]] = []

    for index, raw_alert in enumerate(alerts):
        print(f"Processing alert {index + 1}/{len(alerts)}...")
        normalized_alert = normalizer.normalize(raw_alert)
        sanitized = sanitizer.sanitize_log(normalized_alert)
        processed_alerts.append(sanitized)

    final_output = {
        "case_id": str(case_id),
        "total_alerts": len(processed_alerts),
        "alerts_data": processed_alerts,
    }

    filename = f"test/test_alert_Cortex_Case_{case_id}.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)

    print(
        f"[+] {len(processed_alerts)} Cortex alert(s) normalized, anonymized, "
        f"and successfully saved to: {filename}"
    )
    return final_output, alerts


def _extract_cortex_context(raw_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract hosts, users, SHA256 hashes, and epoch timestamps from Cortex alerts."""
    ctx: dict[str, Any] = {"hosts": set(), "users": set(), "hashes": set(), "ts": []}
    hash_keys = (
        "actor_process_image_sha256",
        "action_process_image_sha256",
        "action_file_sha256",
        "causality_actor_process_image_sha256",
    )
    ts_keys = ("detection_timestamp", "local_insert_ts", "event_timestamp")

    for alert in raw_alerts:
        if alert.get("host_name"):
            ctx["hosts"].add(alert["host_name"])
        if alert.get("user_name"):
            ctx["users"].add(alert["user_name"])
        for key in hash_keys:
            if alert.get(key):
                ctx["hashes"].add(alert[key])
        for key in ts_keys:
            if isinstance(alert.get(key), (int, float)):
                ctx["ts"].append(int(alert[key]))
                break

    return ctx


def _run_xql_query(
    base_url: str,
    headers: dict[str, str],
    query: str,
    from_ms: int,
    to_ms: int,
    max_wait: int = 120,
) -> list[dict[str, Any]]:
    """Execute an XQL query against Cortex XDR and poll until results are ready."""
    start_resp = requests.post(
        f"{base_url}/public_api/v1/xql/start_xql_query",
        headers=headers,
        timeout=30,
        json={"request_data": {"query": query, "timeframe": {"from": from_ms, "to": to_ms}}},
    )
    if start_resp.status_code != 200:
        print(f"[-] start_xql_query HTTP {start_resp.status_code}: {start_resp.text}")
        return []
    query_id = start_resp.json().get("reply")

    deadline = time.time() + max_wait
    while time.time() < deadline:
        res_resp = requests.post(
            f"{base_url}/public_api/v1/xql/get_query_results",
            headers=headers,
            timeout=30,
            json={
                "request_data": {
                    "query_id": query_id,
                    "pending_flag": True,
                    "limit": 1000,
                    "format": "json",
                }
            },
        )
        if res_resp.status_code != 200:
            print(f"[-] get_query_results HTTP {res_resp.status_code}: {res_resp.text}")
            return []

        reply = res_resp.json().get("reply", {})
        status = reply.get("status")
        if status in ("SUCCESS", "PARTIAL_SUCCESS"):
            return (reply.get("results") or {}).get("data", [])
        if status not in ("PENDING", None):
            print(f"[-] XQL ended with status {status}: {reply}")
            return []
        time.sleep(3)

    print("[-] Timed out waiting for XQL results")
    return []


def get_cortex_additional_logs(
    raw_alerts: dict[str, Any] | list[dict[str, Any]],
    client: str,
    window_minutes: int = 30,
    limit: int = 50,
    sanitizer: AdvancedTelemetrySanitizer | None = None,
) -> str:
    """Query Cortex XDR XQL around the alert timeframe and return sanitized telemetry lines."""
    print("\n🔍 Extracting context from Cortex alert(s) for XQL query...")

    if isinstance(raw_alerts, dict):
        raw_alerts = [raw_alerts]

    api_token, endpoint, auth_id = cortexApi(client)
    base_url = endpoint.rstrip("/")
    headers = {
        "x-xdr-auth-id": str(auth_id),
        "Authorization": api_token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }

    ctx = _extract_cortex_context(raw_alerts)
    print(f"   [>] Hosts: {ctx['hosts']} | Users: {ctx['users']} | Hashes: {len(ctx['hashes'])}")

    def in_list(field: str, values: set[str]) -> str:
        vals = ", ".join(f'"{_query_escape(v)}"' for v in values)
        return f"{field} in ({vals})"

    conditions: list[str] = []
    if ctx["hosts"]:
        conditions.append(in_list("agent_hostname", ctx["hosts"]))
    if ctx["users"]:
        conditions.append(in_list("actor_effective_username", ctx["users"]))
    if ctx["hashes"]:
        conditions.append(in_list("actor_process_image_sha256", ctx["hashes"]))
        conditions.append(in_list("action_file_sha256", ctx["hashes"]))

    if not conditions or not ctx["ts"]:
        return "--- ADDITIONAL TELEMETRY ---\nNo contextual data available for query."

    query = (
        "dataset = xdr_data "
        f"| filter {' or '.join(conditions)} "
        "| fields _time, event_type, event_sub_type, agent_hostname, actor_effective_username, "
        "actor_process_image_name, actor_process_command_line, actor_process_image_path, "
        "actor_process_image_sha256, actor_process_os_pid, "
        "causality_actor_process_image_name, causality_actor_process_command_line, "
        "action_file_path, action_file_name, action_file_sha256, "
        "action_remote_ip, action_remote_port, dns_query_name, action_registry_key_name "
        f"| sort asc _time | limit {limit}"
    )

    margin_ms = window_minutes * 60 * 1000
    from_ms, to_ms = min(ctx["ts"]) - margin_ms, max(ctx["ts"]) + margin_ms
    print(f"   [>] Query: {query}")
    print(f"   [>] Window (ms): {from_ms} -> {to_ms}")

    try:
        results = _run_xql_query(base_url, headers, query, from_ms, to_ms)
    except Exception as exc:
        print(f"[-] XQL error: {exc!r}")
        return "--- ADDITIONAL TELEMETRY ---\nXQL query failed."

    if not results:
        return "--- ADDITIONAL TELEMETRY ---\nNo additional events found in the timeframe."

    normalizer = CortexXQLToECSNormalizer()
    normalized = [normalizer.normalize(ev) for ev in results]

    sanitizer = sanitizer or AdvancedTelemetrySanitizer()
    sanitized = sanitizer.sanitize_log({"events": normalized})["events"]

    lines = ["--- ADDITIONAL TELEMETRY (CORTEX XDR XQL, SANITIZED) ---"]
    lines.extend(_format_telemetry_event(ev) for ev in sanitized)
    formatted = "\n".join(lines) + "\n"

    print(formatted)
    return formatted


if __name__ == "__main__":
    alert_sample = get_alert_s1("01a18be9-fab8-7f94-928c-36d7bf2838fe")
    if alert_sample:
        print(alert_sample[1])
        print(alert_sample[0])