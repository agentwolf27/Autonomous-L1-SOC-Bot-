import pandas as pd
import json
import csv
import os
from datetime import datetime, timedelta
import random
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_sample_alerts(num_alerts=50):
    """Generate sample security alerts for demonstration"""
    
    # Sample IPs (mix of legitimate and suspicious)
    sample_ips = [
        "192.168.1.100", "10.0.0.15", "172.16.0.20",  # Internal IPs
        "185.220.101.42", "94.102.49.190", "198.98.51.189",  # Suspicious IPs
        "8.8.8.8", "1.1.1.1", "208.67.222.222",  # Legitimate external
        "45.33.32.156", "167.172.203.244", "104.248.169.218"  # Mixed
    ]
    
    event_types = [
        "Failed Login Attempt", "Malware Detection", "Port Scan", 
        "Suspicious Network Traffic", "Unauthorized Access", "DDoS Attack",
        "Data Exfiltration", "Privilege Escalation", "SQL Injection",
        "Cross-Site Scripting", "Brute Force Attack", "Phishing Attempt"
    ]
    
    descriptions = [
        "Multiple failed login attempts detected",
        "Malicious file detected in downloads folder",
        "Port scanning activity from external IP",
        "Unusual outbound traffic pattern detected",
        "Unauthorized access to sensitive file",
        "High volume traffic indicating DDoS",
        "Large data transfer to external destination",
        "User privilege escalation detected",
        "SQL injection attempt in web application",
        "Malicious script detected in web form",
        "Rapid-fire authentication attempts",
        "Suspicious email with malicious link"
    ]
    
    alerts = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(num_alerts):
        alert = {
            "id": f"ALERT-{i+1:04d}",
            "timestamp": (base_time + timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "source_ip": random.choice(sample_ips),
            "destination_ip": random.choice(sample_ips),
            "event_type": random.choice(event_types),
            "description": random.choice(descriptions),
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "curl/7.68.0", "python-requests/2.25.1", "Wget/1.20.3"
            ]),
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "bytes_transferred": random.randint(100, 100000),
            "status": "New"
        }
        alerts.append(alert)
    
    return alerts

def read_json_alerts(file_path):
    """Read alerts from JSON file"""
    try:
        with open(file_path, 'r') as f:
            alerts = json.load(f)
        logger.info(f"Successfully read {len(alerts)} alerts from {file_path}")
        return alerts
    except FileNotFoundError:
        logger.warning(f"File {file_path} not found")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return []

def read_csv_alerts(file_path):
    """Read alerts from CSV file"""
    try:
        alerts = []
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            alerts = list(reader)
        logger.info(f"Successfully read {len(alerts)} alerts from {file_path}")
        return alerts
    except FileNotFoundError:
        logger.warning(f"File {file_path} not found")
        return []
    except Exception as e:
        logger.error(f"Error reading CSV {file_path}: {e}")
        return []

def normalize_alerts(alerts):
    """Normalize alert data into standardized format"""
    normalized = []
    
    for alert in alerts:
        # Ensure required fields exist with defaults
        normalized_alert = {
            "id": alert.get("id", "UNKNOWN"),
            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            "source_ip": alert.get("source_ip", alert.get("src_ip", "0.0.0.0")),
            "destination_ip": alert.get("destination_ip", alert.get("dst_ip", "0.0.0.0")),
            "event_type": alert.get("event_type", alert.get("type", "Unknown")),
            "description": alert.get("description", alert.get("desc", "No description")),
            "severity": alert.get("severity", "Low"),
            "user_agent": alert.get("user_agent", "Unknown"),
            "source_port": int(alert.get("source_port", alert.get("src_port", 0))),
            "destination_port": int(alert.get("destination_port", alert.get("dst_port", 0))),
            "protocol": alert.get("protocol", "TCP"),
            "bytes_transferred": int(alert.get("bytes_transferred", alert.get("bytes", 0))),
            "status": alert.get("status", "New")
        }
        normalized.append(normalized_alert)
    
    return normalized

def ingest_alerts(json_file=None, csv_file=None, use_sample=True):
    """
    Main ingestion function that reads alerts from various sources
    and returns a normalized Pandas DataFrame
    """
    alerts = []
    
    # Read from JSON file if provided
    if json_file and os.path.exists(json_file):
        alerts.extend(read_json_alerts(json_file))
    
    # Read from CSV file if provided  
    if csv_file and os.path.exists(csv_file):
        alerts.extend(read_csv_alerts(csv_file))
    
    # Generate sample data if no real data found or use_sample is True
    if not alerts or use_sample:
        logger.info("Generating sample alerts for demonstration")
        alerts = generate_sample_alerts()
    
    # Normalize the alert data
    normalized_alerts = normalize_alerts(alerts)
    
    # Convert to DataFrame
    df = pd.DataFrame(normalized_alerts)
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Sort by timestamp
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    logger.info(f"Successfully ingested {len(df)} alerts")
    
    return df

if __name__ == "__main__":
    # Test the ingestion
    alerts_df = ingest_alerts()
    print(f"Ingested {len(alerts_df)} alerts")
    print(alerts_df.head()) 