#!/usr/bin/env python3
"""
Enterprise Integrations Module
Connects SOC bot with Wazuh, The Hive, and Sysmon
"""

import requests
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WazuhIntegration:
    """Integration with Wazuh SIEM"""

    def __init__(self, wazuh_url: str, username: str, password: str):
        self.base_url = wazuh_url.rstrip("/")
        self.username = username
        self.password = password
        self.token = None
        self.authenticate()

    def authenticate(self):
        """Authenticate with Wazuh API"""
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode()

            headers = {
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json",
            }

            response = requests.get(auth_url, headers=headers, verify=False)
            if response.status_code == 200:
                self.token = response.json()["data"]["token"]
                logger.info("Successfully authenticated with Wazuh")
            else:
                logger.error(
                    f"Failed to authenticate with Wazuh: {response.status_code}"
                )
        except Exception as e:
            logger.error(f"Wazuh authentication error: {e}")

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Fetch alerts from Wazuh"""
        try:
            alerts_url = f"{self.base_url}/security/events"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }

            params = {
                "limit": limit,
                "sort": "-timestamp",
                "q": "rule.level:>=7",  # High severity alerts
            }

            response = requests.get(
                alerts_url, headers=headers, params=params, verify=False
            )
            if response.status_code == 200:
                alerts = response.json()["data"]["affected_items"]
                logger.info(f"Retrieved {len(alerts)} alerts from Wazuh")
                return self.normalize_wazuh_alerts(alerts)
            else:
                logger.error(f"Failed to fetch Wazuh alerts: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error fetching Wazuh alerts: {e}")
            return []

    def normalize_wazuh_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Convert Wazuh alerts to our standard format"""
        normalized = []
        for alert in alerts:
            try:
                normalized_alert = {
                    "id": alert.get(
                        "id", f"WAZUH-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    ),
                    "timestamp": alert.get("timestamp", datetime.now().isoformat()),
                    "source_ip": alert.get("data", {}).get("srcip", "unknown"),
                    "destination_ip": alert.get("data", {}).get("dstip", "unknown"),
                    "event_type": alert.get("rule", {}).get("description", "unknown"),
                    "severity": self.map_wazuh_severity(
                        alert.get("rule", {}).get("level", 0)
                    ),
                    "raw_log": alert.get("full_log", ""),
                    "agent_name": alert.get("agent", {}).get("name", "unknown"),
                    "rule_id": alert.get("rule", {}).get("id", "unknown"),
                    "mitre_attack": alert.get("rule", {}).get("mitre", []),
                }
                normalized.append(normalized_alert)
            except Exception as e:
                logger.error(f"Error normalizing Wazuh alert: {e}")
        return normalized

    def map_wazuh_severity(self, level: int) -> str:
        """Map Wazuh rule levels to our severity"""
        if level >= 12:
            return "critical"
        elif level >= 7:
            return "high"
        elif level >= 4:
            return "medium"
        else:
            return "low"


class TheHiveIntegration:
    """Integration with The Hive case management"""

    def __init__(self, hive_url: str, api_key: str):
        self.base_url = hive_url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def create_case(self, alert_data: Dict) -> Optional[str]:
        """Create a case in The Hive"""
        try:
            case_url = f"{self.base_url}/api/case"

            case_data = {
                "title": f"Security Alert: {alert_data.get('event_type', 'Unknown')}",
                "description": f"""
                Alert ID: {alert_data.get('id')}
                Source IP: {alert_data.get('source_ip')}
                Timestamp: {alert_data.get('timestamp')}
                Severity: {alert_data.get('severity')}
                
                Raw Log:
                {alert_data.get('raw_log', 'No raw log available')}
                """,
                "severity": self.map_severity_to_hive(
                    alert_data.get("severity", "low")
                ),
                "tlp": 2,  # TLP:AMBER
                "tags": [
                    f"source_ip:{alert_data.get('source_ip')}",
                    f"severity:{alert_data.get('severity')}",
                    f"rule_id:{alert_data.get('rule_id', 'unknown')}",
                ],
            }

            response = requests.post(
                case_url, headers=self.headers, json=case_data, verify=False
            )
            if response.status_code == 201:
                case_id = response.json().get("id")
                logger.info(f"Created The Hive case: {case_id}")
                return case_id
            else:
                logger.error(f"Failed to create The Hive case: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error creating The Hive case: {e}")
            return None

    def add_observable(self, case_id: str, observable_type: str, value: str) -> bool:
        """Add observable to The Hive case"""
        try:
            observable_url = f"{self.base_url}/api/case/{case_id}/artifact"

            observable_data = {
                "dataType": observable_type,  # ip, domain, hash, etc.
                "data": value,
                "tlp": 2,
                "ioc": True,
                "message": f"Automatically extracted from security alert",
            }

            response = requests.post(
                observable_url, headers=self.headers, json=observable_data, verify=False
            )
            if response.status_code == 201:
                logger.info(f"Added observable {value} to case {case_id}")
                return True
            else:
                logger.error(f"Failed to add observable: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error adding observable: {e}")
            return False

    def map_severity_to_hive(self, severity: str) -> int:
        """Map our severity to The Hive severity"""
        mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return mapping.get(severity.lower(), 1)


class SysmonIntegration:
    """Integration with Sysmon logs"""

    def __init__(self, log_path: str = None):
        self.log_path = (
            log_path
            or "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
        )
        self.event_types = {
            1: "Process Creation",
            2: "File Creation Time Changed",
            3: "Network Connection",
            5: "Process Terminated",
            7: "Image Loaded",
            8: "CreateRemoteThread",
            10: "Process Accessed",
            11: "File Created",
            12: "Registry Event",
            13: "Registry Value Set",
            22: "DNS Query",
        }

    def parse_sysmon_events(self, events: List[Dict]) -> List[Dict]:
        """Parse Sysmon events into our standard format"""
        parsed_events = []

        for event in events:
            try:
                event_id = event.get("EventID", 0)
                event_data = event.get("EventData", {})

                parsed_event = {
                    "id": f"SYSMON-{event.get('RecordID', 'unknown')}",
                    "timestamp": event.get("TimeCreated", datetime.now().isoformat()),
                    "source_ip": event_data.get("SourceIp", "unknown"),
                    "destination_ip": event_data.get("DestinationIp", "unknown"),
                    "event_type": self.event_types.get(
                        event_id, f"Sysmon Event {event_id}"
                    ),
                    "process_name": event_data.get("Image", "unknown"),
                    "command_line": event_data.get("CommandLine", ""),
                    "user": event_data.get("User", "unknown"),
                    "computer_name": event.get("Computer", "unknown"),
                    "raw_log": json.dumps(event, indent=2),
                }

                # Assess risk based on event type and content
                parsed_event["risk_score"] = self.calculate_sysmon_risk(parsed_event)
                parsed_events.append(parsed_event)

            except Exception as e:
                logger.error(f"Error parsing Sysmon event: {e}")

        return parsed_events

    def calculate_sysmon_risk(self, event: Dict) -> int:
        """Calculate risk score for Sysmon events"""
        risk_score = 0

        # High-risk processes
        high_risk_processes = [
            "powershell.exe",
            "cmd.exe",
            "rundll32.exe",
            "regsvr32.exe",
        ]
        if any(
            proc in event.get("process_name", "").lower()
            for proc in high_risk_processes
        ):
            risk_score += 30

        # Suspicious command line patterns
        suspicious_patterns = [
            "base64",
            "encoded",
            "bypass",
            "hidden",
            "downloadstring",
        ]
        if any(
            pattern in event.get("command_line", "").lower()
            for pattern in suspicious_patterns
        ):
            risk_score += 40

        # Network connections to external IPs
        dest_ip = event.get("destination_ip", "")
        if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.")):
            risk_score += 20

        # Registry modifications
        if "Registry" in event.get("event_type", ""):
            risk_score += 15

        return min(risk_score, 100)


class EnterpriseSOCIntegrator:
    """Main integration orchestrator"""

    def __init__(self, config: Dict):
        self.config = config
        self.wazuh = None
        self.hive = None
        self.sysmon = None

        # Initialize integrations based on config
        if config.get("wazuh"):
            self.wazuh = WazuhIntegration(
                config["wazuh"]["url"],
                config["wazuh"]["username"],
                config["wazuh"]["password"],
            )

        if config.get("hive"):
            self.hive = TheHiveIntegration(
                config["hive"]["url"], config["hive"]["api_key"]
            )

        if config.get("sysmon"):
            self.sysmon = SysmonIntegration(config["sysmon"].get("log_path"))

    def collect_all_alerts(self) -> List[Dict]:
        """Collect alerts from all integrated sources"""
        all_alerts = []

        # Collect from Wazuh
        if self.wazuh:
            wazuh_alerts = self.wazuh.get_alerts()
            all_alerts.extend(wazuh_alerts)
            logger.info(f"Collected {len(wazuh_alerts)} alerts from Wazuh")

        # Process Sysmon events (would need additional log parsing in real implementation)
        if self.sysmon:
            # In real implementation, you'd parse actual Sysmon logs
            logger.info(
                "Sysmon integration ready (requires log parsing implementation)"
            )

        return all_alerts

    def create_case_for_alert(self, alert: Dict) -> Optional[str]:
        """Create a case in The Hive for high-severity alerts"""
        if self.hive and alert.get("severity") in ["high", "critical"]:
            case_id = self.hive.create_case(alert)
            if case_id:
                # Add IP observables
                if alert.get("source_ip") and alert["source_ip"] != "unknown":
                    self.hive.add_observable(case_id, "ip", alert["source_ip"])
                if alert.get("destination_ip") and alert["destination_ip"] != "unknown":
                    self.hive.add_observable(case_id, "ip", alert["destination_ip"])
            return case_id
        return None


# Example configuration
ENTERPRISE_CONFIG = {
    "wazuh": {
        "url": "https://your-wazuh-server:55000",
        "username": "wazuh",
        "password": "your-password",
    },
    "hive": {"url": "https://your-hive-server:9000", "api_key": "your-api-key"},
    "sysmon": {"log_path": "/var/log/sysmon.log"},  # Linux path for forwarded logs
}


def main():
    """Example usage of enterprise integrations"""
    integrator = EnterpriseSOCIntegrator(ENTERPRISE_CONFIG)

    # Collect alerts from all sources
    alerts = integrator.collect_all_alerts()

    # Process each alert
    for alert in alerts:
        print(f"Processing alert: {alert['id']}")

        # Create case for high-severity alerts
        case_id = integrator.create_case_for_alert(alert)
        if case_id:
            print(f"Created case {case_id} for alert {alert['id']}")


if __name__ == "__main__":
    main()
