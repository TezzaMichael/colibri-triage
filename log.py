import requests
from api import s1Api, cortexApi
from normalizer import SentinelOneToECSNormalizer, CortexToECSNormalizer
from sanitizer import AdvancedTelemetrySanitizer

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

def get_alert_s1(target_uuid):
    print("Fetching specific alert from SentinelOne (GraphQL)...")
    endpoint = f"{os.getenv('URL_S1')}/unifiedalerts/graphql"
    
    headers = {
        "Authorization": f"ApiToken {s1Api()}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "query": """
            query GetRawData($alertId: ID!) {
                alert(id: $alertId) {
                    rawData
                }
            }
        """,
        "variables": {
            "alertId": target_uuid
        }
    }
    
    response = requests.post(endpoint, headers=headers, json=payload)
    if response.status_code != 200:
        print(f"HTTP Error: {response.text}")
        return
        
    data = response.json().get("data", {}).get("alert", {}).get("rawData")
    if isinstance(data, str):
        try:
            raw_alert = json.loads(data)
        except json.JSONDecodeError:
            print("Error parsing rawData JSON.")
            return
    else:
        raw_alert = data

    if not raw_alert:
        print("No raw data found.")
        return

    normalizer = SentinelOneToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    
    # 1. Normalization based on the actual rawData structure
    normalized_alert = normalizer.normalize(raw_alert)
    
    # 2. Sanitization of sensitive entities
    sanitized = sanitizer.sanitize_log(normalized_alert)
    
    # 3. Saving the output result
    filename = "test/test_alert_S1_unified.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)
        
    print(f"[+] Alert normalized, anonymized, and successfully saved to: {filename}")

    return sanitized


def get_alert_cortex(case_id, client):
    print(f"Fetching alert for Case ID {case_id} from Cortex XDR...")
    
    API_TOKEN, ENDPOINT, ID = cortexApi(client)
    CORTEX_FQDN = ENDPOINT.rstrip('/') 
    
    headers = {
        "x-xdr-auth-id": str(ID),
        "Authorization": API_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    
    endpoint = f"{CORTEX_FQDN}/public_api/v1/incidents/get_incident_extra_data"
    
    payload = {
        "request_data": {
            "incident_id": str(case_id) 
        }
    }
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"HTTP/Connection error to Cortex: {e}")
        return None
        
    json_response = response.json()
    
    # ---------------------------------------------------------
    # CORRECT EXTRACTION: Navigate down to the 'data' array
    # ---------------------------------------------------------
    alerts_container = json_response.get("reply", {}).get("alerts", {})
    
    # Cortex returns a dictionary with {"total_count": X, "data": [...] }
    if isinstance(alerts_container, dict) and "data" in alerts_container:
        alerts = alerts_container["data"]
    elif isinstance(alerts_container, list):
        # Fallback in case a different API version returns the list directly
        alerts = alerts_container
    else:
        alerts = []
        
    if not alerts or len(alerts) == 0:
        print(f"No alerts found for Case ID {case_id}.")
        return None

    print(f"[!] Found {len(alerts)} REAL alert(s) associated with Case ID {case_id}.")

    normalizer = CortexToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    
    processed_alerts = []
    
    for index, raw_alert in enumerate(alerts):
        print(f"Processing alert {index + 1}/{len(alerts)}...")
        
        # 1. Normalization
        normalized_alert = normalizer.normalize(raw_alert)
        
        # 2. Sanitization
        sanitized = sanitizer.sanitize_log(normalized_alert)
        
        processed_alerts.append(sanitized)
    
    # 3. Saving the combined output result
    final_output = {
        "case_id": str(case_id),
        "total_alerts": len(processed_alerts),
        "alerts_data": processed_alerts
    }
    
    filename = f"test/test_alert_Cortex_Case_{case_id}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)
        
    print(f"[+] {len(processed_alerts)} Cortex alert(s) normalized, anonymized, and successfully saved to: {filename}")
    
    return final_output