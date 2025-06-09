import pandas as pd
import requests
import time
import logging
import ipaddress
from typing import Dict, Any
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MITRE ATT&CK mapping for common attack types
MITRE_ATTACK_MAPPING = {
    "Failed Login Attempt": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
    "Malware Detection": ["T1566 - Phishing", "T1204 - User Execution"],
    "Port Scan": ["T1046 - Network Service Scanning", "T1595 - Active Scanning"],
    "Suspicious Network Traffic": [
        "T1071 - Application Layer Protocol",
        "T1041 - Exfiltration Over C2 Channel",
    ],
    "Unauthorized Access": ["T1078 - Valid Accounts", "T1021 - Remote Services"],
    "DDoS Attack": [
        "T1498 - Network Denial of Service",
        "T1499 - Endpoint Denial of Service",
    ],
    "Data Exfiltration": [
        "T1041 - Exfiltration Over C2 Channel",
        "T1048 - Exfiltration Over Alternative Protocol",
    ],
    "Privilege Escalation": [
        "T1068 - Exploitation for Privilege Escalation",
        "T1134 - Access Token Manipulation",
    ],
    "SQL Injection": [
        "T1190 - Exploit Public-Facing Application",
        "T1059 - Command and Scripting Interpreter",
    ],
    "Cross-Site Scripting": [
        "T1190 - Exploit Public-Facing Application",
        "T1203 - Exploitation for Client Execution",
    ],
    "Brute Force Attack": ["T1110 - Brute Force", "T1110.001 - Password Guessing"],
    "Phishing Attempt": ["T1566 - Phishing", "T1566.001 - Spearphishing Attachment"],
}

# Known malicious IP ranges and suspicious IPs for simulation
SUSPICIOUS_IP_PATTERNS = [
    "185.220.",  # Known Tor exit nodes
    "94.102.",  # Known malicious infrastructure
    "198.98.",  # Suspicious hosting
    "45.33.",  # Cloud hosting often used maliciously
    "167.172.",  # Another cloud provider
    "104.248.",  # Digital Ocean ranges often abused
]


def is_private_ip(ip_str):
    """Check if IP is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def get_whois_info(ip_address):
    """
    Simulate WHOIS lookup - in production, use actual WHOIS API
    """
    try:
        # Simulate different responses based on IP patterns
        if is_private_ip(ip_address):
            return {
                "organization": "Internal Network",
                "country": "Local",
                "asn": "AS-INTERNAL",
                "network": "Private Network",
            }

        # Simulate legitimate services
        if ip_address in ["8.8.8.8", "1.1.1.1", "208.67.222.222"]:
            return {
                "organization": (
                    "Google LLC" if "8.8.8.8" in ip_address else "Cloudflare Inc."
                ),
                "country": "US",
                "asn": "AS15169" if "8.8.8.8" in ip_address else "AS13335",
                "network": "Public DNS Service",
            }

        # Simulate suspicious IPs
        if any(pattern in ip_address for pattern in SUSPICIOUS_IP_PATTERNS):
            orgs = [
                "Anonymous Hosting",
                "Bulletproof Hosting",
                "Suspicious Cloud",
                "Unknown Provider",
            ]
            countries = ["RU", "CN", "IR", "KP", "Unknown"]
            return {
                "organization": random.choice(orgs),
                "country": random.choice(countries),
                "asn": f"AS{random.randint(1000, 99999)}",
                "network": "Suspicious Network",
            }

        # Default legitimate response
        return {
            "organization": "Legitimate ISP",
            "country": "US",
            "asn": f"AS{random.randint(1000, 50000)}",
            "network": "Commercial Network",
        }

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {ip_address}: {e}")
        return {
            "organization": "Unknown",
            "country": "Unknown",
            "asn": "Unknown",
            "network": "Unknown",
        }


def get_abuse_score(ip_address):
    """
    Simulate AbuseIPDB lookup - in production, use actual AbuseIPDB API
    """
    try:
        # Internal IPs get 0 score
        if is_private_ip(ip_address):
            return 0

        # Known good IPs
        if ip_address in ["8.8.8.8", "1.1.1.1", "208.67.222.222"]:
            return 0

        # Suspicious IPs get higher scores
        if any(pattern in ip_address for pattern in SUSPICIOUS_IP_PATTERNS):
            return random.randint(60, 100)

        # Random low score for other IPs
        return random.randint(0, 30)

    except Exception as e:
        logger.error(f"Abuse score lookup failed for {ip_address}: {e}")
        return 0


def get_mitre_tags(event_type):
    """
    Map event type to MITRE ATT&CK techniques
    """
    return MITRE_ATTACK_MAPPING.get(event_type, ["T1001 - Data Obfuscation"])


def enrich_single_alert(row):
    """
    Enrich a single alert with external data
    """
    source_ip = row["source_ip"]
    dest_ip = row["destination_ip"]
    event_type = row["event_type"]

    # Get WHOIS info for source IP
    source_whois = get_whois_info(source_ip)
    dest_whois = get_whois_info(dest_ip)

    # Get abuse scores
    source_abuse_score = get_abuse_score(source_ip)
    dest_abuse_score = get_abuse_score(dest_ip)

    # Get MITRE ATT&CK tags
    mitre_tags = get_mitre_tags(event_type)

    # Calculate overall risk factors
    risk_factors = []

    if source_abuse_score > 50:
        risk_factors.append("High Abuse Score")

    if any(pattern in source_ip for pattern in SUSPICIOUS_IP_PATTERNS):
        risk_factors.append("Suspicious Source IP")

    if source_whois["country"] in ["RU", "CN", "IR", "KP"]:
        risk_factors.append("High-Risk Country")

    if row["destination_port"] in [22, 23, 135, 139, 445]:
        risk_factors.append("High-Risk Port")

    if row["severity"] in ["High", "Critical"]:
        risk_factors.append("High Severity")

    # Calculate threat score based on various factors
    threat_score = 0
    threat_score += min(source_abuse_score, 50)  # Cap at 50
    threat_score += min(dest_abuse_score, 30)    # Cap at 30
    if source_whois["country"] in ["RU", "CN", "IR", "KP"]:
        threat_score += 20
    if len(risk_factors) > 2:
        threat_score += 15
    if row["severity"] in ["High", "Critical"]:
        threat_score += 10
    
    # Normalize to 0-100
    threat_score = min(threat_score, 100)

    return {
        "source_whois_org": source_whois["organization"],
        "source_whois_country": source_whois["country"],
        "source_whois_asn": source_whois["asn"],
        "dest_whois_org": dest_whois["organization"],
        "dest_whois_country": dest_whois["country"],
        "source_abuse_score": source_abuse_score,
        "dest_abuse_score": dest_abuse_score,
        "mitre_tags": ", ".join(mitre_tags),
        "risk_factors": ", ".join(risk_factors) if risk_factors else "None",
        "is_internal_traffic": is_private_ip(source_ip) and is_private_ip(dest_ip),
        "external_source": not is_private_ip(source_ip),
        "external_dest": not is_private_ip(dest_ip),
        "threat_score": threat_score,
        "geo_country": source_whois["country"],  # Add geo_country for tests
    }


def enrich_alerts(df):
    """
    Main enrichment function that adds contextual information to alerts

    Args:
        df: Pandas DataFrame with alert data

    Returns:
        Enhanced DataFrame with additional columns
    """
    logger.info(f"Starting enrichment for {len(df)} alerts")

    # Handle empty DataFrame
    if df.empty:
        logger.warning("Empty DataFrame provided for enrichment")
        return df.copy()

    # Create a copy to avoid modifying original
    enriched_df = df.copy()

    # Initialize new columns
    enrichment_columns = [
        "source_whois_org",
        "source_whois_country",
        "source_whois_asn",
        "dest_whois_org",
        "dest_whois_country",
        "source_abuse_score",
        "dest_abuse_score",
        "mitre_tags",
        "risk_factors",
        "is_internal_traffic",
        "external_source",
        "external_dest",
        "threat_score",
        "geo_country",
    ]

    for col in enrichment_columns:
        enriched_df[col] = None

    # Process each alert
    for idx, row in enriched_df.iterrows():
        try:
            enrichment_data = enrich_single_alert(row)

            # Update the DataFrame with enrichment data
            for key, value in enrichment_data.items():
                enriched_df.at[idx, key] = value

            # Rate limiting simulation
            time.sleep(0.01)  # Small delay to simulate API calls

        except Exception as e:
            logger.error(f"Failed to enrich alert {row.get('id', idx)}: {e}")
            # Set default values for failed enrichments
            for col in enrichment_columns:
                if enriched_df.at[idx, col] is None:
                    enriched_df.at[idx, col] = "Unknown" if "score" not in col else 0

    logger.info(f"Enrichment completed for {len(enriched_df)} alerts")

    return enriched_df


if __name__ == "__main__":
    # Test enrichment with sample data
    from ingestion import ingest_alerts

    # Get sample alerts
    alerts_df = ingest_alerts()
    print(f"Original alerts: {len(alerts_df)}")

    # Enrich alerts
    enriched_df = enrich_alerts(alerts_df)
    print(f"Enriched alerts: {len(enriched_df)}")
    print("\nEnrichment columns added:")
    print(
        enriched_df[
            ["id", "source_ip", "source_abuse_score", "mitre_tags", "risk_factors"]
        ].head()
    )
