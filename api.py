"""Credential retrieval helpers for external security platforms via the IOC Manager."""

import json
import os
import sys

import requests
import urllib3
from dotenv import load_dotenv

# Suppress warnings from self-signed certificates on internal endpoints.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

_RAW_CLIENTS = os.getenv("CLIENT_LIST", "")


def get_s1_api_key() -> str:
    """Return the API token for SentinelOne."""
    api_token, _, _ = get_api_key("SentinelOne")
    return api_token


def get_cortex_credentials(client: str) -> tuple[str, str, str]:
    """Validate the client against the allowed list and return its Cortex credentials."""
    allowed_clients = {c.strip() for c in _RAW_CLIENTS.split(",") if c.strip()}
    if client not in allowed_clients:
        print("CLIENT NOT FOUND")
        sys.exit(1)

    return get_api_key(client)


def get_api_key(service: str) -> tuple[str, str, str]:
    """Fetch (api_token, endpoint, auth_id) for the given service from the IOC Manager."""
    print("GETTING API KEY...")
    url = os.getenv("URL_IOC", "")
    payload = {
        "service": service,
        "passcode": os.getenv("PASSCODE_IOC"),
    }

    response = requests.post(url, verify=False, json=payload)
    if response.status_code != 200:
        print("ERROR API KEY")
        sys.exit(1)

    try:
        record = response.json()["data"][0]
        api_token = record["apikey"]
        endpoint = record["endpoint"]

        # Palo Alto XDR requires an additional auth ID header stored in additional_info.
        if "paloaltonetworks" in endpoint:
            auth_id = json.loads(record["additional_info"])["xdr-auth-id"]
        else:
            auth_id = ""

        print("API KEY ACQUIRED")
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        print("API KEY NOT FOUND")
        sys.exit(1)

    return api_token, endpoint, auth_id