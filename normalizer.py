import json

class SentinelOneToECSNormalizer:
    """Converts native SentinelOne alerts into the standardized and enriched ECS format."""
    
    def normalize(self, s1_alert):
        resources = s1_alert.get("resources", [{}])
        resource = resources[0] if resources else {}
        s1_meta = resource.get("s1_metadata", {})
        
        finding_info = s1_alert.get("finding_info", {})
        
        evidences = s1_alert.get("evidences", [{}])
        evidence = evidences[0] if evidences else {}
        process = evidence.get("process", {})
        file_info = process.get("file", {})
        user_info = process.get("user", {})
        parent_process = process.get("parent_process", {})
        
        # Multiple hash extraction
        hashes = {}
        for h in file_info.get("hashes", []):
            if h.get("algorithm_id") == 2:
                hashes["sha1"] = h.get("value")
            elif h.get("algorithm_id") == 3:
                hashes["sha256"] = h.get("value")

        # MITRE ATT&CK extraction
        tactics, techniques = [], []
        for event in finding_info.get("related_events", []):
            for attack in event.get("attacks", []):
                tactic_info = attack.get("tactic", {})
                if tactic_info.get("name"):
                    tactics.append(tactic_info.get("name"))
                tech_info = attack.get("technique", {})
                if tech_info.get("uid"):
                    techniques.append(tech_info.get("uid"))

        ecs_event = {
            "event": {
                # Correctly retrieves the S1 alert internal_uid (with fallback to uid)
                "id": str(finding_info.get("internal_uid") or s1_alert.get("uid")),
                "kind": "alert",
                "category": ["intrusion_detection", "malware"],
                "type": ["info"],
                "provider": "SentinelOne",
                "action": s1_alert.get("status_name", "Unknown"),
                "severity": s1_alert.get("severity_id")
            },
            "@timestamp": s1_alert.get("time"),
            "host": {
                "name": resource.get("name"),
                "domain": s1_meta.get("site_name"),
                "os": {
                    "name": resource.get("type")
                }
            },
            "user": {
                "name": user_info.get("name") or user_info.get("display_name")
            },
            "file": {
                "name": file_info.get("name"),
                "path": file_info.get("path"),
                "size": file_info.get("size"),
                "hash": hashes
            },
            "process": {
                "name": process.get("name"),
                "pid": process.get("pid"),
                "command_line": process.get("cmd_line"),
                "executable": file_info.get("path"),
                "parent": {
                    "name": parent_process.get("name"),
                    "pid": parent_process.get("pid"),
                    "command_line": parent_process.get("cmd_line")
                }
            },
            "threat": {
                "indicator": {
                    "confidence": s1_alert.get("severity")
                },
                "enrichments": {
                    "mitre_tactics": list(set(tactics)),
                    "mitre_techniques": list(set(techniques))
                },
                "description": finding_info.get("desc")
            }
        }
        return ecs_event

class CortexToECSNormalizer:
    """Converts native Cortex XDR alerts into the standard ECS format aligned with SentinelOne."""
    
    def normalize(self, cortex_alert):
        # 1. Host IP (Takes the first one if multiple are present)
        host_ip_raw = cortex_alert.get("host_ip")
        host_ip = host_ip_raw.split(",")[0].strip() if host_ip_raw else None
        
        # 2. Domain / User handling
        user_name_raw = cortex_alert.get("user_name") or ""
        domain = cortex_alert.get("agent_device_domain")
        user_name = user_name_raw
        if "\\" in user_name_raw:
            domain_extracted, user_name = user_name_raw.split("\\", 1)
            if not domain:
                domain = domain_extracted

        # 3. File and Process (Action vs Actor)
        file_name = cortex_alert.get("action_process_image_name") or cortex_alert.get("actor_process_image_name")
        file_path = cortex_alert.get("action_process_image_command_line") or cortex_alert.get("actor_process_command_line")
        sha256 = cortex_alert.get("action_process_image_sha256") or cortex_alert.get("actor_process_image_sha256")

        # 4. MITRE ATT&CK
        tactics = [cortex_alert.get("mitre_tactic_id_and_name")] if cortex_alert.get("mitre_tactic_id_and_name") else []
        techniques = [cortex_alert.get("mitre_technique_id_and_name")] if cortex_alert.get("mitre_technique_id_and_name") else []

        ecs_event = {
            "event": {
                "id": str(cortex_alert.get("alert_id")),
                "kind": "alert",
                "category": [cortex_alert.get("category", "intrusion_detection")],
                "type": [cortex_alert.get("alert_type", "Unclassified")],
                "provider": "CortexXDR",
                "action": cortex_alert.get("action_pretty", "Unknown"),
                "severity": cortex_alert.get("severity")
            },
            "@timestamp": cortex_alert.get("detection_timestamp"),
            "host": {
                "name": cortex_alert.get("host_name"),
                "domain": domain,
                "ip": host_ip,
                "os": {
                    "name": cortex_alert.get("agent_os_type"),
                    "version": cortex_alert.get("agent_os_sub_type")
                }
            },
            "user": {
                "name": user_name
            },
            "file": {
                "name": file_name,
                "path": file_path,
                "hash": {
                    "sha256": sha256
                }
            },
            "process": {
                "name": cortex_alert.get("actor_process_image_name"),
                "pid": cortex_alert.get("actor_process_os_pid"),
                "command_line": cortex_alert.get("actor_process_command_line"),
                "executable": cortex_alert.get("actor_process_image_path"),
                "parent": {
                    "name": cortex_alert.get("causality_actor_process_image_name"),
                    "command_line": cortex_alert.get("causality_actor_process_command_line")
                }
            },
            "threat": {
                "indicator": {
                    "confidence": cortex_alert.get("severity")
                },
                "enrichments": {
                    "mitre_tactics": tactics,
                    "mitre_techniques": techniques
                },
                "description": cortex_alert.get("description")
            }
        }

        # Optional common network block (e.g., ARP discovery or remote connections)
        remote_ip = cortex_alert.get("action_remote_ip")
        if remote_ip:
            ecs_event["network"] = {
                "destination": {
                    "ip": remote_ip,
                    "domain": cortex_alert.get("action_external_hostname"),
                    "port": cortex_alert.get("action_remote_port")
                }
            }

        return ecs_event