import json
import requests
import sys
import os
from dotenv import load_dotenv

import urllib3
# Disable insecure HTTPS warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from the .env file
load_dotenv()
raw_clients = os.getenv("CLIENT_LIST", "")

def s1Api():
    """Retrieve API credentials for SentinelOne."""
    key = get_api_key("SentinelOne")
    return key[0]

def cortexApi(client):
    """Validate client existence against the environment whitelist and fetch Cortex API keys."""
    list_clients = [client.strip() for client in raw_clients.split(",") if client.strip()]
    if client in list_clients:
        return get_api_key(client)
    
    print("CLIENT NOT FOUND")
    sys.exit(1)

def xurrentApi():
    """Retrieve API credentials for Xurrent."""
    key = get_api_key("Xurrent")
    return key

def get_api_key(service):
    """Request and parse API keys and endpoints from the centralized IOC Manager service."""
    print("GETTING API KEY...")
    url = os.getenv("URL_IOC")
    data = {
        'service': service,
        'passcode': os.getenv("PASSCODE_IOC")
    }
    
    response = requests.post(url, verify=False, json=data)
    if response.status_code == 200:
        try:
            response = response.json()['data'][0]
            api_token = response['apikey']
            endpoint = response['endpoint']
            
            # Extract specific XDR authentication ID if Palo Alto Networks endpoint is detected
            if "paloaltonetworks" in endpoint:
                id = json.loads(response['additional_info'])['xdr-auth-id']
            else:
                id = ""
                
            print("API KEY ACQUIRED")
        except (KeyError, IndexError, json.JSONDecodeError):
            print("API KEY NOT FOUND")
            sys.exit(1)
    else:
        print("ERROR API KEY")
        sys.exit(1)
        
    return api_token, endpoint, id