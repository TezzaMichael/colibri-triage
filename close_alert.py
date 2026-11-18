"""Alert and incident closure helpers for SentinelOne (Unified Alerts GraphQL) and Cortex XDR."""

import json
import os
from typing import Any

import requests

from api import cortexApi, s1Api

MAX_COMMENT = 2000


class CloseError(Exception):
    """Raised when a platform rejects or fails to confirm an alert closure."""


def get_analysts() -> list[dict[str, str | None]]:
    """Parse ANALYST_LIST from the environment (`email` or `email|s1_user_id` entries)."""
    analysts: list[dict[str, str | None]] = []
    for raw_entry in os.getenv("ANALYST_LIST", "").split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        email, _, uid = entry.partition("|")
        analysts.append({"email": email.strip(), "s1_user_id": uid.strip() or None})
    return analysts


# ---------------------------------------------------------------------------
# SentinelOne (Unified Alert Management GraphQL)
# ---------------------------------------------------------------------------
S1_VERDICT_PREFIX = {
    "true_positive": "TRUE_POSITIVE",
    "false_positive": "FALSE_POSITIVE",
}

# Candidate action IDs for assignment (undocumented in public schema; tried sequentially).
S1_ASSIGN_ACTION_IDS = ("S1/alert/assign", "S1/alert/assignUser")

_ENUM_CACHE: dict[str, list[str]] = {}


def _action_add_note(text: str) -> str:
    return f'{{id: "S1/alert/addNote", payload: {{note: {{value: {json.dumps(text)}}}}}}}'


def _action_verdict(verdict: str) -> str:
    # Enum literals must remain unquoted in GraphQL payloads.
    return f'{{id: "S1/alert/analystVerdictUpdate", payload: {{analystVerdict: {{value: {verdict}}}}}}}'


def _action_status(value: str) -> str:
    return f'{{id: "S1/alert/statusUpdate", payload: {{status: {{value: {value}}}}}}}'


def _s1_graphql(query: str) -> dict[str, Any]:
    endpoint = f"{os.getenv('URL_S1', '').rstrip('/')}/unifiedalerts/graphql"
    headers = {
        "Authorization": f"ApiToken {s1Api()}",
        "Content-Type": "application/json",
    }
    resp = requests.post(endpoint, headers=headers, json={"query": query}, timeout=30)
    if resp.status_code != 200:
        raise CloseError(f"SentinelOne HTTP {resp.status_code}: {resp.text[:500]}")

    body = resp.json()
    if body.get("errors"):
        # Preserve start and end of long GraphQL errors since expected types appear at the end.
        messages = []
        for err in body["errors"]:
            msg = str(err.get("message", err))
            if len(msg) > 700:
                msg = f"{msg[:250]} [...] {msg[-400:]}"
            messages.append(msg)
        raise CloseError("SentinelOne GraphQL error: " + " | ".join(messages))

    return body.get("data") or {}


def _s1_enum_values(enum_name: str) -> list[str]:
    """Introspect and cache allowed enum values from the SentinelOne GraphQL schema."""
    if enum_name not in _ENUM_CACHE:
        query = f'query {{ __type(name: "{enum_name}") {{ enumValues {{ name }} }} }}'
        type_info = _s1_graphql(query).get("__type") or {}
        _ENUM_CACHE[enum_name] = [e["name"] for e in type_info.get("enumValues") or []]
    return _ENUM_CACHE[enum_name]


def _pick_status_resolved() -> str:
    values = _s1_enum_values("Status")
    if "RESOLVED" not in values:
        raise CloseError(f"SentinelOne Status has no RESOLVED value. Available: {values}")
    return "RESOLVED"


def _pick_verdict(resolution: str, detail: str | None) -> str:
    """Validate the requested verdict against the console's AnalystVerdict enum."""
    values = _s1_enum_values("AnalystVerdict")
    prefix = S1_VERDICT_PREFIX[resolution]
    verdict = detail or f"{prefix}_UNDEFINED"
    if verdict not in values or not verdict.startswith(prefix):
        accepted = [v for v in values if v.startswith(prefix)]
        raise CloseError(
            f"Verdict '{verdict}' is not valid for {resolution.replace('_', ' ')}. "
            f"Accepted values: {accepted}"
        )
    return verdict


def _s1_user_id(assignee: dict[str, str | None]) -> int:
    """Resolve the numeric SentinelOne user ID from config or via REST /users lookup."""
    if assignee.get("s1_user_id"):
        return int(assignee["s1_user_id"])

    base = os.getenv("URL_S1", "").rstrip("/")
    headers = {"Authorization": f"ApiToken {s1Api()}", "Content-Type": "application/json"}
    email = assignee["email"] or ""

    for params in ({"email": email}, {"query": email}):
        resp = requests.get(f"{base}/users", headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise CloseError(f"User lookup HTTP {resp.status_code}: {resp.text[:200]}")
        for user in resp.json().get("data") or []:
            if (user.get("email") or "").lower() == email.lower():
                return int(user["id"])

    raise CloseError(
        f"User {email} not found on SentinelOne (or token lacks user-read permissions). "
        f"Set it explicitly in .env as '{email}|<user_id>'."
    )


def _s1_assign(alert_id: str, scope: str, user_id: int) -> None:
    succeeded = 0
    errors: list[str] = []
    for action_id in S1_ASSIGN_ACTION_IDS:
        action = f'{{id: "{action_id}", payload: {{assignUser: {{value: {user_id}}}}}}}'
        try:
            _s1_trigger(alert_id, scope, action, "assign")
            succeeded += 1
        except CloseError as exc:
            errors.append(f"{action_id}: {str(exc)[:200]}")

    if not succeeded:
        raise CloseError("; ".join(errors))


def _s1_scope_literal(raw_alert: dict[str, Any]) -> str:
    meta = ((raw_alert.get("resources") or [{}])[0].get("s1_metadata")) or {}
    if meta.get("site_id"):
        return f"{{scopeType: SITE, scopeIds: [{json.dumps(str(meta['site_id']))}]}}"
    if meta.get("account_id"):
        return f"{{scopeType: ACCOUNT, scopeIds: [{json.dumps(str(meta['account_id']))}]}}"
    raise CloseError("Cannot determine SentinelOne scope (site or account) from alert metadata.")


def _s1_trigger(alert_id: str, scope: str, action: str, step: str) -> None:
    flt = f'{{or: [{{and: [{{fieldId: "id", stringEqual: {{value: {json.dumps(alert_id)}}}}}]}}]}}'
    query = (
        f"mutation {{ alertTriggerActions(scope: {scope}, viewType: ALL, filter: {flt}, "
        f"actions: [{action}]) {{ __typename }} }}"
    )
    data = _s1_graphql(query)
    typename = (data.get("alertTriggerActions") or {}).get("__typename", "")
    if "Error" in typename:
        raise CloseError(f"SentinelOne rejected step '{step}' ({typename}).")


def _s1_verify(alert_id: str) -> tuple[str | None, str | None] | None:
    """Re-fetch the alert to confirm its updated status and verdict."""
    query = f"query {{ alert(id: {json.dumps(alert_id)}) {{ status analystVerdict }} }}"
    try:
        alert = (_s1_graphql(query).get("alert")) or {}
        return alert.get("status"), alert.get("analystVerdict")
    except Exception:
        return None


def close_alert_s1(
    raw_alert: dict[str, Any],
    alert_id: str,
    resolution: str,
    comment: str,
    verdict_detail: str | None = None,
    assignee: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    """Assign, comment, set verdict, and resolve an alert in SentinelOne."""
    scope = _s1_scope_literal(raw_alert)
    warnings: list[str] = []

    # Validate enums upfront so an invalid value cannot leave the alert partially updated.
    verdict = _pick_verdict(resolution, verdict_detail)
    status = _pick_status_resolved()

    # Assign before resolving, as some consoles reject assignment on closed alerts.
    if assignee:
        try:
            _s1_assign(alert_id, scope, _s1_user_id(assignee))
        except Exception as exc:
            warnings.append(f"Could not assign alert to {assignee['email']}: {str(exc)[:300]}")

    if comment:
        _s1_trigger(alert_id, scope, _action_add_note(comment[:MAX_COMMENT]), "note")
    _s1_trigger(alert_id, scope, _action_verdict(verdict), "verdict")
    _s1_trigger(alert_id, scope, _action_status(status), "status")

    # alertTriggerActions can return success without applying changes; verify the final state.
    verified = _s1_verify(alert_id)
    if verified is None:
        warnings.append("Could not verify updated status on SentinelOne.")
    elif str(verified[0]).upper() != "RESOLVED":
        raise CloseError(
            f"SentinelOne accepted the request, but alert status is still '{verified[0]}'."
        )

    return {"platform": "SentinelOne", "verified": verified is not None, "warnings": warnings}


# ---------------------------------------------------------------------------
# Cortex XDR (Incidents)
# ---------------------------------------------------------------------------
CORTEX_RESOLUTIONS = {
    "false_positive": [
        "resolved_false_positive",
        "resolved_known_issue",
        "resolved_duplicate",
        "resolved_other",
    ],
    "true_positive": [
        "resolved_true_positive",
        "resolved_threat_handled",
        "resolved_security_testing",
    ],
}


def _cortex_headers(client: str) -> tuple[str, dict[str, str]]:
    token, endpoint, auth_id = cortexApi(client)
    headers = {
        "x-xdr-auth-id": str(auth_id),
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    return endpoint.rstrip("/"), headers


def _cortex_update(
    base: str, headers: dict[str, str], case_id: str, update: dict[str, Any]
) -> tuple[bool, str]:
    resp = requests.post(
        f"{base}/public_api/v1/incidents/update_incident",
        headers=headers,
        timeout=30,
        json={"request_data": {"incident_id": str(case_id), "update_data": update}},
    )
    if resp.status_code != 200:
        return False, f"Cortex HTTP {resp.status_code}: {resp.text[:500]}"

    reply = resp.json().get("reply")
    if reply is False or (isinstance(reply, dict) and reply.get("err_code")):
        return False, f"Cortex rejected update: {json.dumps(reply)[:500]}"
    return True, ""


def close_incident_cortex(
    case_id: str,
    client: str,
    resolution: str,
    comment: str,
    verdict_detail: str | None = None,
    assignee: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    """Update, assign, and resolve an incident in Cortex XDR."""
    allowed = CORTEX_RESOLUTIONS[resolution]
    status = verdict_detail or allowed[0]
    if status not in allowed:
        raise CloseError(
            f"Status '{status}' is not valid for {resolution.replace('_', ' ')}. Accepted: {allowed}"
        )

    base, headers = _cortex_headers(client)
    update: dict[str, Any] = {"status": status}
    if comment:
        update["resolve_comment"] = comment[:MAX_COMMENT]

    warnings: list[str] = []
    ok, err = False, ""
    if assignee:
        ok, err = _cortex_update(
            base, headers, case_id, {**update, "assigned_user_mail": assignee["email"]}
        )
        if not ok:
            warnings.append(f"Could not assign incident to {assignee['email']} ({err[:200]})")

    # Retry without assignee if assignment failed so the incident still closes.
    if not ok:
        ok, err = _cortex_update(base, headers, case_id, update)
        if not ok:
            raise CloseError(err)

    verified = False
    try:
        resp = requests.post(
            f"{base}/public_api/v1/incidents/get_incident_extra_data",
            headers=headers,
            timeout=30,
            json={"request_data": {"incident_id": str(case_id)}},
        )
        current = ((resp.json().get("reply") or {}).get("incident") or {}).get("status")
        if current and current != status:
            raise CloseError(f"Cortex accepted the request, but incident status is '{current}'.")
        verified = bool(current)
    except CloseError:
        raise
    except Exception:
        pass

    if not verified:
        warnings.append("Could not verify updated status on Cortex XDR.")

    return {"platform": "Cortex XDR", "verified": verified, "warnings": warnings}


# ---------------------------------------------------------------------------
# GraphQL Schema Inspection CLI
# ---------------------------------------------------------------------------
_TYPE_FRAGMENT = """
fragment T on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"""


def _type_str(type_ref: dict[str, Any] | None) -> str:
    """Format a nested GraphQL __Type reference into SDL notation (e.g. [ActionInput!]!)."""
    if not type_ref:
        return "?"
    if type_ref["kind"] == "NON_NULL":
        return f"{_type_str(type_ref.get('ofType'))}!"
    if type_ref["kind"] == "LIST":
        return f"[{_type_str(type_ref.get('ofType'))}]"
    return type_ref.get("name") or "?"


def _named(type_ref: dict[str, Any] | None) -> str | None:
    while type_ref and not type_ref.get("name"):
        type_ref = type_ref.get("ofType")
    return type_ref.get("name") if type_ref else None


def debug_s1_schema() -> None:
    """Introspect and print argument and input types for alertTriggerActions."""
    query = (
        'query { __type(name: "Mutation") { fields { name args { name type { ...T } } } } }'
        + _TYPE_FRAGMENT
    )
    fields = _s1_graphql(query)["__type"]["fields"]
    field = next((f for f in fields if f["name"] == "alertTriggerActions"), None)
    if not field:
        print("alertTriggerActions not found. Mutations:", [f["name"] for f in fields])
        return

    print("alertTriggerActions(")
    pending: list[str | None] = []
    for arg in field["args"]:
        print(f"    {arg['name']}: {_type_str(arg['type'])}")
        pending.append(_named(arg["type"]))
    print(")\n")

    seen: set[str] = set()
    while pending and len(seen) < 25:
        name = pending.pop(0)
        if not name or name in seen or name.startswith("__"):
            continue
        seen.add(name)

        type_query = (
            f'query {{ __type(name: "{name}") {{ kind inputFields {{ name type {{ ...T }} }} '
            "enumValues { name } } }"
        ) + _TYPE_FRAGMENT
        type_def = _s1_graphql(type_query).get("__type")
        if not type_def or type_def["kind"] == "SCALAR":
            continue

        print(f"{type_def['kind']} {name}")
        for fld in type_def.get("inputFields") or []:
            print(f"    {fld['name']}: {_type_str(fld['type'])}")
            pending.append(_named(fld["type"]))
        for val in type_def.get("enumValues") or []:
            print(f"    {val['name']}")
        print()


def debug_s1_alert_type() -> None:
    """Introspect and print fields on Alert and alertAvailableActions."""
    query = (
        'query { __type(name: "Query") { fields { name args { name type { ...T } } type { ...T } } } }'
        + _TYPE_FRAGMENT
    )
    fields = _s1_graphql(query)["__type"]["fields"]
    action_field = next((x for x in fields if x["name"] == "alertAvailableActions"), None)

    if action_field:
        args_sig = ", ".join(
            f"{a['name']}: {_type_str(a['type'])}" for a in action_field["args"]
        )
        print(f"alertAvailableActions({args_sig})")
        print("  returns", _type_str(action_field["type"]), "\n")
        target_types = [_named(action_field["type"]), "Alert"]
    else:
        target_types = ["Alert"]

    for name in target_types:
        if not name:
            continue
        type_query = (
            f'query {{ __type(name: "{name}") {{ kind fields {{ name type {{ ...T }} }} }} }}'
            + _TYPE_FRAGMENT
        )
        type_def = _s1_graphql(type_query).get("__type")
        if type_def:
            print(f"{type_def['kind']} {name}")
            for fld in type_def.get("fields") or []:
                print(f"    {fld['name']}: {_type_str(fld['type'])}")
            print()


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()
    debug_s1_schema()
    for enum in ("AnalystVerdict", "Status"):
        print(f"ENUM {enum}: {_s1_enum_values(enum)}")
    debug_s1_alert_type()