import json
import re
import hashlib
import ipaddress

import os
from dotenv import load_dotenv
load_dotenv()


class AdvancedTelemetrySanitizer:
    def __init__(self, salt=str(os.getenv("SALT_PASSWORD", "default_salt"))):
        self.salt = salt
        self.mapping_table = {}

    def _get_hash(self, value, prefix):
        """Generates, stores, and returns a consistent hash, excluding public IP addresses."""
        if not value or len(str(value)) < 3: 
            return str(value)
            
        val_str = str(value)

        # Bypass for public IPs
        if prefix == "IP":
            try:
                ip_obj = ipaddress.ip_address(val_str)
                # is_private natively checks if the IP belongs to RFC 1918 / reserved ranges
                if not ip_obj.is_private:
                    return val_str
            except ValueError:
                pass # If the string is not a valid IP, proceed with standard masking
                
        if val_str not in self.mapping_table:
            hash_val = hashlib.sha256(f"{val_str}{self.salt}".encode()).hexdigest()[:8]
            self.mapping_table[val_str] = f"{prefix.upper()}-{hash_val}"
            
        return self.mapping_table[val_str]

    def _harvest_entities(self, data):
        """Phase 1: Navigates the JSON structure and harvests entities based on the ECS standard."""
        if isinstance(data, dict):
            # Search within the 'host' block typical of the ECS standard
            if 'host' in data and isinstance(data['host'], dict):
                host_info = data['host']
                if host_info.get('name'):
                    self._get_hash(str(host_info['name']), "HOST")
                if host_info.get('domain'):
                    # Changed from "HOST" to "DOMAIN"
                    self._get_hash(str(host_info['domain']), "DOMAIN") 
                if host_info.get('ip'):
                    self._get_hash(str(host_info['ip']), "IP")
            
            # Search within the 'user' block typical of the ECS standard
            if 'user' in data and isinstance(data['user'], dict):
                user_info = data['user']
                if user_info.get('name') and user_info.get('name') not in ["NT AUTHORITY\\SYSTEM", "SYSTEM", "root"]:
                    self._get_hash(str(user_info['name']), "USER")

            # Recursion to explore any nested lists or dictionaries
            for key, val in data.items():
                if isinstance(val, (dict, list)):
                    self._harvest_entities(val)
                    
        elif isinstance(data, list):
            for item in data:
                self._harvest_entities(item)

    def sanitize_log(self, log_entry):
        # 1. Populate the mapping table with explicit data from this alert
        self._harvest_entities(log_entry)
        
        # 2. Convert everything to string for global replacement
        log_str = json.dumps(log_entry)
        
        # 3. Regex masking for scattered elements (MAC, IPv4, IPv6)
        # MAC Address
        macs = re.findall(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b', log_str)
        for mac in set(macs):
            log_str = log_str.replace(mac, self._get_hash(mac, "MAC"))
            
        # IPv4 (intentionally tolerant regex)
        ipv4s = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_str)
        for ip in set(ipv4s):
            log_str = log_str.replace(ip, self._get_hash(ip, "IP"))
            
        # IPv6
        ipv6s = re.findall(r'(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{0,4}', log_str)
        for ip in set(ipv6s):
            if len(ip) > 6: # Avoid false positives on short strings
                log_str = log_str.replace(ip, self._get_hash(ip, "IP"))

        # 4. Global replacement of entities (Names, Domains, Users) wherever they appear
        # Sort from longest to shortest string to prevent partial replacements
        sorted_entities = sorted(self.mapping_table.keys(), key=len, reverse=True)
        for entity in sorted_entities:
            # Replace only if the clear-text entity is still present
            log_str = log_str.replace(entity, self.mapping_table[entity])
                
        return json.loads(log_str)