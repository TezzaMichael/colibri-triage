import json
import math
import requests
import time
from openai import OpenAI
from log import get_alert_s1, get_alert_cortex

URL_SYSTEMONE = "http://127.0.0.1:8000/v1/systemone"
URL_CHAT = "http://127.0.0.1:8000/v1"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer colibri-key"
}


def systemone(context):
    print("📡 STEP 1: System One Classification...\n")

    payload = {
        "state": context,
        "questions": {
            "alert_classification": {
                "type": "choice",
                "instructions": "Is this alert a True Positive or a False Positive?",
                "criteria": {
                    "True Positive": None,
                    "False Positive": None
                }
            }
        }
    }

    start_time = time.time()
    response = requests.post(URL_SYSTEMONE, json=payload, headers=HEADERS)
    elapsed_s1 = time.time() - start_time

    result = response.json()
    answers = result["answers"]["alert_classification"]
    classification = answers["choice"]
    
    # Calculate entropy based on probabilities
    tp = answers["probabilities"]["True Positive"] * math.log2(answers["probabilities"]["True Positive"]) if answers["probabilities"]["True Positive"] > 0 else 0
    fp = answers["probabilities"]["False Positive"] * math.log2(answers["probabilities"]["False Positive"]) if answers["probabilities"]["False Positive"] > 0 else 0
    print(f"tp: {tp} --> probability: {answers['probabilities']['True Positive']}")
    print(f"fp: {fp} --> probability: {answers['probabilities']['False Positive']}")
    entropy = -(tp + fp)

    print("=" * 55)
    print(f"🏆 Classification: {classification} (Entropy: {entropy:.2f})")
    print(f"⏱️ System One Time: {elapsed_s1:.3f} s")
    print("=" * 55)

    return entropy, classification

def colibri_text(context, classification):
    print("\n💬 STEP 2: Generating Reasoning...\n")

    # Optimized prompt: removing probabilities and explicitly forbidding mentioning them
    reasoning_prompt = f"""You have classified the following alert as: "{classification}".

    ALERT CONTEXT:
    {context}

    INSTRUCTIONS:
    Briefly and directly explain WHY you chose "{classification}", relying EXCLUSIVELY on the technical details of the context (e.g., duration, server type, absence of deploy, metrics).
    STRICT RULE: DO NOT mention percentages, probabilities, confidence scores, or mathematical calculations. Keep it concise (maximum 2-3 sentences or bullet points)."""

    client = OpenAI(base_url=URL_CHAT, api_key="colibri-key")

    start_time = time.time()
    token_count = 0

    stream = client.chat.completions.create(
        model="qwen3.6-colibri",
        messages=[
            {"role": "system", "content": "You are an expert system analyst. Respond in a technical, direct, and concise manner."},
            {"role": "user", "content": reasoning_prompt}
        ],
        stream=True,
        max_tokens=150  
    )

    print("🤖 REASONING:")
    reasoning_text = ""
    for chunk in stream:
        if chunk.choices[0].delta.content is not None:
            content = chunk.choices[0].delta.content
            reasoning_text += content
            print(content, end="", flush=True)
            token_count += 1

    elapsed_chat = time.time() - start_time
    tok_per_sec = token_count / elapsed_chat if elapsed_chat > 0 else 0

    print("\n")
    print("-" * 55)
    print(f"⏱️ Generation Time   : {elapsed_chat:.3f} s")
    print(f"⚡ Real-time Speed   : {tok_per_sec:.2f} tok/s")
    print(f"📝 Tokens Generated  : {token_count} (out of max 150)")
    print("=" * 55)

    return reasoning_text




if __name__ == '__main__':
    context = get_alert_cortex(13209)
    entropy, classification = systemone(context)

    if entropy < 0.5:
        colibri_text(context, classification)
    else:
        print("OTHER LOG")