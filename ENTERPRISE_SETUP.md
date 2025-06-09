# Enterprise SOC Integration Setup Guide

This guide shows how to integrate our SOC automation bot with real enterprise security tools like **Wazuh**, **The Hive**, and **Sysmon**.

## 🏗️ Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Sysmon    │    │   Wazuh     │    │  The Hive   │
│ (Endpoint)  │───▶│   (SIEM)    │───▶│ (Case Mgmt) │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │   SOC Automation    │
                │       Bot           │
                └─────────────────────┘
```

## 🔧 Tool Setup

### 1. Wazuh SIEM Setup

**Installation (Ubuntu/Debian):**
```bash
# Install Wazuh server
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update && sudo apt-get install wazuh-manager

# Start Wazuh services
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Install Wazuh dashboard (Kibana)
sudo apt-get install wazuh-dashboard
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

**Configuration:**
```yaml
# /var/ossec/etc/ossec.conf
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>
  
  <rules>
    <include>rules_config.xml</include>
    <include>local_rules.xml</include>
  </rules>
  
  <syscheck>
    <disabled>no</disabled>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
  </syscheck>
</ossec_config>
```

### 2. The Hive Case Management

**Installation (Docker):**
```bash
# Clone The Hive repository
git clone https://github.com/TheHive-Project/TheHive.git
cd TheHive

# Start with Docker Compose
docker-compose -f docker/thehive5-cassandra-elasticsearch.yml up -d
```

**Configuration:**
```hocon
# application.conf
play.http.secret.key = "your-secret-key-here"

db.janusgraph {
  storage.backend = cassandra
  storage.hostname = ["cassandra"]
  storage.port = 9042
}

storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/files
}

services {
  cortex {
    servers = [
      {
        name = local
        url = "http://cortex:9001"
        auth {
          type = "bearer"
          key = "your-cortex-api-key"
        }
      }
    ]
  }
}
```

### 3. Sysmon Endpoint Monitoring

**Windows Installation:**
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "."

# Install with configuration
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Sysmon Configuration (sysmonconfig.xml):**
```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Process creation -->
    <ProcessCreate onmatch="exclude">
      <Image condition="end with">svchost.exe</Image>
    </ProcessCreate>
    
    <!-- Network connections -->
    <NetworkConnect onmatch="include">
      <Image condition="contains">powershell</Image>
      <Image condition="contains">cmd</Image>
    </NetworkConnect>
    
    <!-- File creation -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">temp</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

## 🔌 Integration Configuration

### Update Configuration File

Create `enterprise_config.json`:
```json
{
  "wazuh": {
    "url": "https://your-wazuh-server:55000",
    "username": "wazuh",
    "password": "your-secure-password",
    "verify_ssl": false
  },
  "hive": {
    "url": "https://your-hive-server:9000",
    "api_key": "your-hive-api-key",
    "organisation": "your-org"
  },
  "sysmon": {
    "log_path": "/var/log/sysmon/sysmon.log",
    "forward_to_wazuh": true
  },
  "enrichment": {
    "virustotal_api_key": "your-vt-api-key",
    "abuseipdb_api_key": "your-abuse-api-key"
  }
}
```

### Install Additional Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# Install enterprise integration dependencies
pip install python-evtx xmltodict thehive4py pywazuh

# Update requirements.txt
echo "python-evtx>=0.7.4" >> requirements.txt
echo "xmltodict>=0.12.0" >> requirements.txt
echo "thehive4py>=1.13.0" >> requirements.txt
echo "pywazuh>=4.3.0" >> requirements.txt
```

## 🚀 Usage Examples

### 1. Run with Enterprise Integrations

```bash
# Run once with enterprise mode
python main.py --mode once --enterprise

# Continuous monitoring with enterprise tools
python main.py --mode continuous --enterprise --interval 30

# Dashboard with enterprise data
python main.py --mode dashboard --enterprise --port 8080
```

### 2. Test Individual Integrations

```python
from integrations import WazuhIntegration, TheHiveIntegration

# Test Wazuh connection
wazuh = WazuhIntegration(
    "https://your-wazuh:55000",
    "wazuh",
    "password"
)
alerts = wazuh.get_alerts(limit=10)
print(f"Retrieved {len(alerts)} alerts from Wazuh")

# Test The Hive case creation
hive = TheHiveIntegration(
    "https://your-hive:9000",
    "your-api-key"
)
case_id = hive.create_case({
    'id': 'TEST-001',
    'event_type': 'Malware Detection',
    'severity': 'high',
    'source_ip': '192.168.1.100'
})
print(f"Created case: {case_id}")
```

## 📊 Real-World Alert Flow

### From Endpoint to Response

1. **Sysmon** detects process creation on Windows endpoint
2. **Wazuh agent** forwards logs to Wazuh manager
3. **Wazuh rules** trigger alerts for suspicious activity
4. **SOC Bot** ingests alerts via Wazuh API
5. **AI Triage** classifies risk level
6. **The Hive** case created for high-risk alerts
7. **Automated response** blocks IPs, creates tickets

### Example Alert Processing

```python
# Real Wazuh alert
wazuh_alert = {
    "id": "1640995200.12345",
    "timestamp": "2024-01-01T10:00:00Z",
    "rule": {
        "id": "100002",
        "description": "Windows Logon Success",
        "level": 8
    },
    "data": {
        "srcip": "192.168.1.100",
        "dstip": "10.0.0.1"
    },
    "agent": {
        "name": "WORKSTATION-01"
    }
}

# Our bot processes it
enriched = enrich_alerts([wazuh_alert])
triaged = triage(enriched)
response = execute_actions(triaged)

# Automatically creates The Hive case for high-risk
```

## 🔍 Monitoring & Troubleshooting

### Check Integration Status

```bash
# Check Wazuh API connectivity
curl -u wazuh:password -k https://your-wazuh:55000/security/user/authenticate

# Check The Hive API
curl -H "Authorization: Bearer your-api-key" https://your-hive:9000/api/status

# Check Sysmon logs
tail -f /var/log/sysmon/sysmon.log
```

### Common Issues

1. **Wazuh Authentication Failure**
   ```bash
   # Reset Wazuh password
   /var/ossec/bin/manage_agents -u wazuh -p new_password
   ```

2. **The Hive Connection Issues**
   ```bash
   # Check The Hive logs
   docker logs thehive_container
   ```

3. **Sysmon Not Forwarding**
   ```bash
   # Check Wazuh agent status
   /var/ossec/bin/agent_control -l
   ```

## 🎯 Performance Tuning

### Wazuh Optimization
```xml
<!-- Increase alert buffer -->
<global>
  <alerts_per_second>1000</alerts_per_second>
  <memory_size>128</memory_size>
</global>
```

### The Hive Scaling
```hocon
# Increase JVM heap
play.server.jvm.memory = "-Xms2g -Xmx4g"

# Cassandra optimization
storage.cassandra.replication-factor = 3
```

## 🏆 Best Practices

1. **Security**
   - Use API keys instead of passwords
   - Enable SSL/TLS for all connections
   - Rotate credentials regularly

2. **Performance**
   - Batch API calls when possible
   - Use async processing for large datasets
   - Monitor API rate limits

3. **Reliability**
   - Implement retry logic with exponential backoff
   - Use health checks for all integrations
   - Log all API interactions for debugging

4. **Scalability**
   - Use message queues for high-volume environments
   - Implement horizontal scaling with multiple bot instances
   - Cache frequently accessed data

---

Your SOC bot now integrates with enterprise-grade security tools, providing real-world threat detection and response capabilities! 🚀 