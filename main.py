import json
import requests
import time 

from api import s1Api, cortexApi, xurrentApi
from sanitizer import AdvancedTelemetrySanitizer
from normalizer import SentinelOneToECSNormalizer, CortexToECSNormalizer

import os
from dotenv import load_dotenv

load_dotenv()

def testS1():
    print("Connessione a SentinelOne e recupero alert in corso...")
    raw_threats = fetch_s1_threats(limit=2)
    
    # Controllo iniziale sulla presenza di dati
    if not raw_threats:
        print("Nessun alert trovato.")
        return

    normalizer = SentinelOneToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    
    # Iterazione sulla lista originale degli alert estratti
    for i, raw_threat in enumerate(raw_threats):
        # 1. Normalizza il singolo alert, non l'intera lista
        normalized_alert = normalizer.normalize(raw_threat)
        
        # 2. Sanitizza l'alert normalizzato
        sanitized = sanitizer.sanitize_log(normalized_alert)
        
        # 3. Genera un nome file dinamico per non sovrascrivere i precedenti
        filename = f"test/test_alert_S1_{i+1}.json"
        
        with open(filename, "w") as f:
            json.dump(sanitized, f, indent=2)
            
        print(f"[+] Alert anonimizzato salvato con successo in: {filename}")

def testCortex():
    print("Connessione a Cortex e recupero alert in corso...")
    raw_threats = fetch_cortex_threats(limit=2)
    
    # Controllo iniziale sulla presenza di dati
    if not raw_threats:
        print("Nessun alert trovato.")
        return

    normalizer = CortexToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    
    # Iterazione sulla lista originale degli alert estratti
    for i, raw_threat in enumerate(raw_threats):
        # 1. Normalizza il singolo alert, non l'intera lista
        normalized_alert = normalizer.normalize(raw_threat)
        
        # 2. Sanitizza l'alert normalizzato
        sanitized = sanitizer.sanitize_log(normalized_alert)
        
        # 3. Genera un nome file dinamico per non sovrascrivere i precedenti
        filename = f"test/test_alert_Cortex_{i+1}.json"
        
        with open(filename, "w") as f:
            json.dump(sanitized, f, indent=2)
            
        print(f"[+] Alert anonimizzato salvato con successo in: {filename}")

def fetch_s1_threats(limit=2):
    API_TOKEN = s1Api()
    endpoint = f"{os.getenv('URL_S1')}/threats"
    headers = {"Authorization": f"ApiToken {API_TOKEN}", "Content-Type": "application/json"}
    params = {"limit": limit, "sortBy": "createdAt", "sortOrder": "desc"}
    response = requests.get(endpoint, headers=headers, params=params)
    response.raise_for_status()
    return response.json().get("data", [])

def fetch_cortex_threats(limit=100, client=""):
    """Estrae gli alert tramite Cortex XDR 5.x API (Standard Auth)"""
    if not client:
        print("CLIENT PARAMETER MISSING")
        return []
    
    API_TOKEN, ENDPOINT, ID = cortexApi(client)
    CORTEX_FQDN = ENDPOINT.rstrip('/') 
    
    endpoint = f"{CORTEX_FQDN}/public_api/v1/alerts/get_alerts"
    
    # 2. Header semplificati (Standard Auth)
    headers = {
        "x-xdr-auth-id": str(ID),
        "Authorization": API_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" # Mantiene aperto il WAF
    }
    
    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": limit,
            "sort": {
                "field": "creation_time",
                "keyword": "desc"
            }
        }
    }
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()

        with open("test/cortex.json", "w") as f:
            json.dump(response.json().get("reply", {}).get("alerts", []), f, indent=2)
        return response.json().get("reply", {}).get("alerts", [])
    except requests.exceptions.RequestException as e:
        print(f"Errore di connessione a Cortex XDR: {e}")
        return []


    
TARGET_ALERTS = 100
def generate_dataset():
    API_TOKEN = s1Api()
    print(f"Avvio estrazione di {TARGET_ALERTS} alert da SentinelOne...")
    endpoint = f"{os.getenv('URL_S1')}/threats"
    headers = {"Authorization": f"ApiToken {API_TOKEN}", "Content-Type": "application/json"}
    
    fetched_threats = []
    cursor = None
    
    # Paginazione per scaricare lotti grandi
    while len(fetched_threats) < TARGET_ALERTS:
        params = {"limit": 100, "sortBy": "createdAt", "sortOrder": "desc"}
        if cursor:
            params["cursor"] = cursor
            
        try:
            response = requests.get(endpoint, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            alerts = data.get("data", [])
            if not alerts:
                break
                
            fetched_threats.extend(alerts)
            cursor = data.get("pagination", {}).get("nextCursor")
            
            if not cursor:
                break
                
            time.sleep(1) # Rate limiting di sicurezza
        except Exception as e:
            print(f"Errore durante l'estrazione: {e}")
            break

    fetched_threats = fetched_threats[:TARGET_ALERTS]
    print(f"Scaricati {len(fetched_threats)} alert. Avvio pipeline di normalizzazione e sanitizzazione...")

    normalizer = SentinelOneToECSNormalizer()
    sanitizer = AdvancedTelemetrySanitizer()
    
    dataset_filename = "soc_eval_dataset.jsonl"
    processed_count = 0

    with open(dataset_filename, "w") as f:
        for threat in fetched_threats:
            # 1. Estrazione Ground Truth (Verdetto reale dell'analista)
            ground_truth = threat.get("threatInfo", {}).get("analystVerdict", "undefined")
            
            # Filtriamo gli undefined per avere solo log analizzati e utili per i test
            if ground_truth == "undefined":
                continue
                
            # 2. Normalizzazione
            ecs_alert = normalizer.normalize(threat)
            
            # 3. Sanitizzazione
            safe_ecs_alert = sanitizer.sanitize_log(ecs_alert)
            
            # 4. Creazione dell'oggetto Dataset
            dataset_entry = {
                "ground_truth": ground_truth,
                "threat_id": threat.get("id"),
                "log_data": safe_ecs_alert
            }
            
            # 5. Scrittura in JSONL (una riga per JSON)
            f.write(json.dumps(dataset_entry) + "\n")
            processed_count += 1

    print(f"\n[+] Dataset generato con successo: {dataset_filename}")
    print(f"[+] Alert processati e salvati (esclusi gli undefined): {processed_count}")

if __name__ == '__main__':
    #testCortex()
    generate_dataset()
    #main()