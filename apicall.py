"""FastAPI backend for alert triage, enrichment, LLM reasoning, and case closure."""

import json
import os
from typing import Any, Literal

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from alert_types import detect_alert_type
from close_alert import MAX_COMMENT, CloseError, close_alert_s1, get_analysts
from colibri import REVIEW_LABEL, build_reasoning_messages, colibri_chat, systemone
from customer_context import build_auth_context
from log import (
    get_alert_cortex,
    get_alert_s1,
    get_cortex_additional_logs,
    get_s1_additional_logs,
)

load_dotenv()

app = FastAPI(title="LLM API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ENTROPY_THRESHOLD = 0.75
MAX_HISTORY_MESSAGES = 12  # Keep the last 6 user/assistant exchanges after the initial prompt.

# In-memory investigation state keyed by alert_id (non-persistent across restarts).
SESSIONS: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------
class AlertRequest(BaseModel):
    console: str
    client: str | None = None
    alert_id: str


class EnrichRequest(BaseModel):
    alert_id: str


class ChatRequest(BaseModel):
    alert_id: str
    message: str


class CloseRequest(BaseModel):
    alert_id: str
    closed_by: str
    resolution: Literal["true_positive", "false_positive"]
    comment: str = ""
    verdict_detail: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def build_context(sanitized: dict[str, Any] | list[Any], extra: str | None = None) -> str:
    """Format the sanitized alert payload and optional telemetry into an LLM prompt block."""
    ctx = "--- ORIGINAL ALERT ---\n" + json.dumps(sanitized, indent=2, ensure_ascii=False)
    if extra:
        ctx += f"\n\n{extra}"
    return ctx


def trim_history(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Preserve the system prompt and initial analysis (first 3 messages), trimming older turns."""
    head, tail = messages[:3], messages[3:]
    return head + tail[-MAX_HISTORY_MESSAGES:]


def start_conversation(
    session: dict[str, Any],
    context: str,
    classification: str,
    review_reasons: list[str] | None = None,
) -> tuple[str, Any]:
    """Generate the initial LLM explanation and initialize the session chat history."""
    messages = build_reasoning_messages(
        context, classification, session["alert_type"], review_reasons
    )
    reasoning, stats = colibri_chat(messages)
    messages.append({"role": "assistant", "content": reasoning})
    session["messages"] = messages
    session["classification"] = classification
    return reasoning, stats


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/clients")
async def get_clients() -> dict[str, list[str]]:
    """Return the configured client list from the environment."""
    raw_clients = os.getenv("CLIENT_LIST", "")
    clients = [c.strip() for c in raw_clients.split(",") if c.strip()]
    return {"clients": clients}


@app.get("/api/analysts")
def list_analysts() -> dict[str, list[str]]:
    """Return the email addresses of analysts authorized to close alerts."""
    return {"analysts": [a["email"] for a in get_analysts()]}


@app.post("/api/analyze")
def analyze_alert(request: AlertRequest) -> dict[str, Any]:
    """Phase 1: fetch the alert, detect its type, and run initial classification."""
    alert_id = request.alert_id
    console = request.console
    client = request.client

    print(f"\n--- STARTING INVESTIGATION: {alert_id} | {console} | {client} ---")

    if console == "Cortex XDR":
        result = get_alert_cortex(alert_id, client)
    else:
        result = get_alert_s1(alert_id)

    if not result:
        return {"status": "error", "message": "Failed to retrieve the alert."}

    sanitized, raw = result
    alert_type, matched = detect_alert_type(raw)
    match_note = f" (matched '{matched}')" if matched else ""
    print(f"[i] Alert type: {alert_type}{match_note}")

    context = build_context(sanitized)
    entropy, classification = systemone(context, alert_type)

    # Auth alerts always require customer context and GeoIP before a verdict is meaningful.
    if alert_type == "authentication":
        needs_enrichment = True
        enrichment_reason = "Authentication alert: checking customer notes and IP geolocation..."
    else:
        needs_enrichment = entropy >= ENTROPY_THRESHOLD
        enrichment_reason = (
            "Initial classification is uncertain (high entropy). "
            "Fetching additional telemetry and re-evaluating..."
        )

    session: dict[str, Any] = {
        "console": console,
        "client": client,
        "sanitized": sanitized,
        "raw": raw,
        "alert_type": alert_type,
        "context": context,
        "classification": classification,
        "messages": None,
    }
    SESSIONS[alert_id] = session

    reasoning, stats = "", None
    if needs_enrichment:
        print(f"\n⚠️ Enrichment needed (entropy {entropy:.2f}). Waiting for /api/enrich...")
    else:
        reasoning, stats = start_conversation(session, context, classification)

    return {
        "status": "success",
        "entropy": round(entropy, 2),
        # Hide the provisional label on auth alerts until enrichment completes.
        "classification": None if alert_type == "authentication" else classification,
        "reasoning": reasoning,
        "stats": stats,
        "alert_type": alert_type,
        "needs_enrichment": needs_enrichment,
        "enrichment_reason": enrichment_reason,
    }


@app.post("/api/enrich")
def enrich_alert(request: EnrichRequest) -> dict[str, Any]:
    """Phase 2: gather additional telemetry, re-classify, and generate the explanation."""
    session = SESSIONS.get(request.alert_id)
    if not session:
        return {"status": "error", "message": "Session not found. Run the analysis first."}

    auth_meta = None
    if session["alert_type"] == "authentication":
        additional, auth_meta = build_auth_context(
            session["console"], session["client"], session["raw"]
        )
    elif session["console"] == "Cortex XDR":
        additional = get_cortex_additional_logs(session["raw"], session["client"])
    else:
        additional = get_s1_additional_logs(session["raw"])

    final_context = build_context(session["sanitized"], additional)
    session["context"] = final_context

    print("🔄 Recalculating System One classification with enriched context...")
    entropy, classification = systemone(final_context, session["alert_type"])

    # Unverifiable auth alerts must never be auto-dismissed as false positives.
    needs_review = entropy >= ENTROPY_THRESHOLD
    review_reasons = None
    if auth_meta and not auth_meta["verifiable"]:
        classification = REVIEW_LABEL
        review_reasons = auth_meta["missing"]
        needs_review = True

    reasoning, stats = start_conversation(session, final_context, classification, review_reasons)

    return {
        "status": "success",
        "entropy": round(entropy, 2),
        "classification": classification,
        "reasoning": reasoning,
        "stats": stats,
        "alert_type": session["alert_type"],
        "extra_logs": additional,
        "needs_manual_review": needs_review,
    }


@app.post("/api/chat")
def chat_with_context(request: ChatRequest) -> dict[str, Any]:
    """Continue the follow-up Q&A session for an analyzed alert."""
    session = SESSIONS.get(request.alert_id)
    if not session:
        return {"reply": "Session not found. Run the analysis first.", "stats": None}

    # Bootstrap minimal history if enrichment was skipped or failed.
    if not session.get("messages"):
        session["messages"] = build_reasoning_messages(
            session["context"], session["classification"], session["alert_type"]
        )
        session["messages"].append(
            {
                "role": "assistant",
                "content": f"Classification: {session['classification']}. Ask me anything about this alert.",
            }
        )

    session["messages"].append({"role": "user", "content": request.message})
    try:
        reply, stats = colibri_chat(trim_history(session["messages"]))
    except Exception as exc:
        session["messages"].pop()
        print(f"[-] Chat error: {exc!r}")
        return {"reply": "The model did not respond. Try again.", "stats": None}

    session["messages"].append({"role": "assistant", "content": reply})
    return {"reply": reply, "stats": stats}


@app.post("/api/close")
def close_alert(request: CloseRequest) -> dict[str, Any]:
    """Close a SentinelOne alert on behalf of the selected analyst."""
    session = SESSIONS.get(request.alert_id)
    if not session:
        return {"status": "error", "message": "Session not found. Run the analysis first."}
    if session["console"] != "SentinelOne":
        return {"status": "error", "message": "Automatic closing is available only for SentinelOne."}

    target_email = request.closed_by.strip().lower()
    assignee = next(
        (a for a in get_analysts() if a["email"].lower() == target_email),
        None,
    )
    if not assignee:
        return {"status": "error", "message": "Analyst not found in ANALYST_LIST."}

    comment = request.comment.strip()[:MAX_COMMENT]
    try:
        result = close_alert_s1(
            session["raw"],
            request.alert_id,
            request.resolution,
            comment,
            verdict_detail=request.verdict_detail,
            assignee=assignee,
        )
    except CloseError as exc:
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        print(f"[-] Close error: {exc!r}")
        return {"status": "error", "message": f"Unexpected error: {exc}"}

    session["closed"] = {"by": assignee["email"], "as": request.resolution}
    return {"status": "success", "warnings": result.get("warnings", [])}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)