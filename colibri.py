"""System One classification and Colibri LLM reasoning client."""

import math
import time
from typing import Any

import requests
from openai import OpenAI

URL_SYSTEMONE = "http://127.0.0.1:8001/v1/systemone"
URL_CHAT = "http://127.0.0.1:8001/v1"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer colibri-key",
}

MAX_REPLY_CHARS = 500  # Prompt-enforced character budget.
MAX_TOKENS = 400       # Safety ceiling (~150 tokens typically covers 500 chars).

REVIEW_LABEL = "Needs Review"

# ---------------------------------------------------------------------------
# System One Classification Guidance
# ---------------------------------------------------------------------------
ENDPOINT_GUIDANCE = {
    "instructions": (
        "Analyze the provided ECS SOC alert context. Classify if this represents a genuine security "
        "threat (True Positive) or legitimate/benign behavior (False Positive)"
    ),
    "criteria": {
        "True Positive": (
            "The activity indicates actual malicious intent, unauthorized access, malware execution, "
            "or a genuine security policy violation that requires analyst intervention."
        ),
        "False Positive": (
            "The activity is a false alarm caused by legitimate system processes, authorized "
            "administrative tasks, authorized backup routines, or normal application behavior."
        ),
    },
}

AUTH_GUIDANCE = {
    "instructions": (
        "Analyze the provided authentication alert context. Decide if this is a genuine account "
        "compromise or policy-violating login (True Positive) or a legitimate login (False Positive). "
        "If a CUSTOMER CONTEXT section is present, use it: a login from a country that the customer "
        "notes describe as legitimate for this user is a False Positive unless other indicators show "
        "compromise. Use only the geolocation given there; never infer the country of an IP yourself."
    ),
    "criteria": {
        "True Positive": (
            "Login from a country or location not justified by the customer notes, impossible travel, "
            "brute force or password spraying, or signs of a compromised account."
        ),
        "False Positive": (
            "Login consistent with the customer notes for that user (expected country, travel, VPN) "
            "and no other signs of compromise."
        ),
    },
}

GUIDANCE = {
    "endpoint": ENDPOINT_GUIDANCE,
    "authentication": AUTH_GUIDANCE,
}


def systemone(context: str, alert_type: str = "endpoint") -> tuple[float, str]:
    """Run System One binary classification and return (shannon_entropy, predicted_label)."""
    print("📡 STEP 1: System One Classification...\n")

    guidance = GUIDANCE.get(alert_type, ENDPOINT_GUIDANCE)
    payload = {
        "state": context,
        "questions": {
            "alert_classification": {
                "type": "choice",
                "instructions": guidance["instructions"],
                "criteria": guidance["criteria"],
            }
        },
    }

    start_time = time.time()
    response = requests.post(URL_SYSTEMONE, json=payload, headers=HEADERS)
    elapsed = time.time() - start_time

    result = response.json()
    print("Systemone:")
    print(result)

    answers = result["answers"]["alert_classification"]
    classification = answers["choice"]

    entropy = 0.0
    for label in ("True Positive", "False Positive"):
        prob = answers["probabilities"].get(label, 0)
        if prob > 0:
            entropy -= prob * math.log2(prob)
            print(f"{label}: probability {prob}")

    print("=" * 55)
    print(f"🏆 Classification: {classification} (Entropy: {entropy:.2f}) [{alert_type}]")
    print(f"⏱️ System One Time: {elapsed:.3f} s")
    print("=" * 55)

    return entropy, classification


# ---------------------------------------------------------------------------
# Reasoning and Chat Prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are an expert SOC analyst. Respond in English in a technical, direct, and concise manner. "
    "You are discussing ONE specific alert with a SOC analyst. Answer follow-up questions using ONLY "
    "the alert context and the previous messages. If the information is not in the context, say so "
    "instead of guessing. Entities in the alert are pseudonymized (HOST-xxxx, USER-xxxx, IP-xxxx): "
    f"refer to them using these identifiers. Every answer MUST be at most {MAX_REPLY_CHARS} characters "
    "long and MUST end with a complete sentence: if you run out of space, drop details, never cut off."
)

EXPLANATION_HINT = {
    "endpoint": "(e.g., anomalous path, obfuscated script, absence of C2 connections, known legitimate process)",
    "authentication": "(e.g., source country versus the customer notes for this user, impossible travel, failed attempts)",
}

ACTIONS = {
    ("endpoint", True): (
        "- RECOMMENDED ACTIONS: 2-3 short steps for containment and mitigation "
        "(e.g., isolate the host, block the IP/hash on the firewall/EDR, disable the user)."
    ),
    ("endpoint", False): (
        "- TUNING AND CLOSURE: how to handle the alert "
        "(e.g., close as 'Expected Behavior', whitelist rule for the hash or file path)."
    ),
    ("authentication", True): (
        "- RECOMMENDED ACTIONS: 2-3 short steps "
        "(e.g., reset credentials, revoke sessions, enforce MFA, block the source IP, contact the customer)."
    ),
    ("authentication", False): (
        "- CLOSURE: how to handle the alert "
        "(e.g., close as expected travel/VPN, suggest updating the customer notes)."
    ),
}


def build_reasoning_messages(
    context: str,
    classification: str,
    alert_type: str = "endpoint",
    review_reasons: list[str] | None = None,
) -> list[dict[str, str]]:
    """Build the initial system + user message pair for explanation or manual-review guidance."""
    kind = alert_type if alert_type in EXPLANATION_HINT else "endpoint"

    if classification == REVIEW_LABEL:
        reasons = "; ".join(review_reasons or ["the available data is not enough"])
        review_prompt = f"""This alert could NOT be verified, so it is NOT classified as True or False Positive: it needs an in-depth review. Missing: {reasons}.

ALERT CONTEXT:
{context}

INSTRUCTIONS:
- WHAT WE KNOW: state in one bullet what the alert reports (user, claimed country, activity).
- WHAT IS MISSING: say exactly what could not be verified and why it blocks a decision.
- NEXT CHECKS: 2 short checks for the analyst (e.g., confirm the travel with the customer, review the sign-in logs and MFA, check other sign-ins of the same user).

STRICT RULES:
- Do NOT call it a False Positive and do NOT say it is legitimate.
- The WHOLE answer must be at most {MAX_REPLY_CHARS} characters. Use 3 short bullet points and finish every bullet.
- DO NOT mention percentages, probabilities, confidence scores, or mathematical calculations."""
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": review_prompt},
        ]

    action_instructions = ACTIONS[(kind, classification == "True Positive")]
    reasoning_prompt = f"""You have classified the following alert as: "{classification}".

ALERT CONTEXT:
{context}

INSTRUCTIONS:
- EXPLANATION: Briefly and directly explain WHY you chose "{classification}", relying EXCLUSIVELY on the technical details of the context {EXPLANATION_HINT[kind]}.
{action_instructions}

STRICT RULES:
- The WHOLE answer must be at most {MAX_REPLY_CHARS} characters. Use 3-4 short bullet points and finish every bullet.
- DO NOT mention percentages, probabilities, confidence scores, or mathematical calculations.
- Keep it highly technical."""

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": reasoning_prompt},
    ]


def _trim_incomplete(text: str) -> str:
    """Drop a trailing incomplete sentence when generation hits max_tokens."""
    cut = max(text.rfind("."), text.rfind("!"), text.rfind("?"), text.rfind("\n"))
    return text[: cut + 1].rstrip() if cut > len(text) * 0.4 else text


def colibri_chat(
    messages: list[dict[str, str]], max_tokens: int = MAX_TOKENS
) -> tuple[str, dict[str, Any]]:
    """Stream a chat completion from Colibri and return (response_text, throughput_stats)."""
    client = OpenAI(base_url=URL_CHAT, api_key="colibri-key")

    start_time = time.time()
    token_count = 0
    finish_reason = None

    stream = client.chat.completions.create(
        model="qwen3.6-colibri",
        messages=messages,
        stream=True,
        max_tokens=max_tokens,
    )

    print("🤖 REASONING:")
    text = ""
    for chunk in stream:
        if not chunk.choices:
            continue
        choice = chunk.choices[0]
        if choice.finish_reason:
            finish_reason = choice.finish_reason
        content = choice.delta.content
        if content is not None:
            text += content
            print(content, end="", flush=True)
            token_count += 1

    elapsed = time.time() - start_time
    tok_per_sec = token_count / elapsed if elapsed > 0 else 0.0

    truncated = finish_reason == "length"
    if truncated:
        text = _trim_incomplete(text)

    truncation_flag = " [TRUNCATED]" if truncated else ""
    print("\n")
    print("-" * 55)
    print(f"⏱️ Generation Time   : {elapsed:.3f} s")
    print(f"⚡ Real-time Speed   : {tok_per_sec:.2f} tok/s")
    print(f"📝 Tokens Generated  : {token_count} (out of max {max_tokens}){truncation_flag}")
    print("=" * 55)

    stats = {
        "tokens": token_count,
        "seconds": round(elapsed, 2),
        "tok_per_sec": round(tok_per_sec, 1),
        "truncated": truncated,
    }
    return text, stats


def colibri_text(
    context: str, classification: str, alert_type: str = "endpoint"
) -> tuple[str, dict[str, Any]]:
    """Run single-turn reasoning for a classified alert."""
    print("\n💬 STEP 2: Generating Reasoning...\n")
    return colibri_chat(build_reasoning_messages(context, classification, alert_type))