# 🛡️ Level 1 SOC Automation Bot

A comprehensive **Level 1 Security Operations Center (SOC) automation bot** built in Python that integrates SIEM ingestion, alert enrichment, AI-powered triage, automated response capabilities, and a real-time web dashboard.

## 🚀 Features

### Core Capabilities
- **🔍 SIEM Integration**: Ingest alerts from JSON/CSV files with normalized data structure
- **🧩 Alert Enrichment**: MITRE ATT&CK mapping plus simulated WHOIS and AbuseIPDB lookups (stubs to replace with real API calls)
- **🤖 AI Triage**: Machine learning-powered risk scoring using scikit-learn
- **⚡ Automated Response**: Intelligent response actions based on risk levels
- **📊 Real-time Dashboard**: Beautiful Flask web interface with live metrics
- **🐳 Docker Support**: Fully containerized for easy deployment

### Alert Processing Pipeline
1. **Data Ingestion** (`ingestion.py`) - Reads and normalizes security alerts
2. **Enrichment** (`enrichment.py`) - Adds threat intelligence and context
3. **AI Triage** (`triage.py`) - ML-based risk assessment and prioritization  
4. **Response Engine** (`response.py`) - Executes automated containment actions
5. **Dashboard** (`dashboard.py`) - Web-based monitoring and visualization

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SIEM      │    │ Enrichment  │    │  AI Triage  │    │  Response   │
│ Ingestion   │───▶│   Engine    │───▶│   Engine    │───▶│   Engine    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    📊 Web Dashboard                                 │
│              Real-time Monitoring & Metrics                        │
└─────────────────────────────────────────────────────────────────────┘
```

## 📦 Installation

### Prerequisites
- Python 3.10+
- Docker (optional)
- 4GB+ RAM recommended

### Quick Start

1. **Clone the repository**
```bash
git clone <repository-url>
cd Autonomous-L1-SOC-Bot-
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the SOC automation bot**
```bash
python main.py
```

4. **Access the dashboard**
Open your browser to `http://localhost:5000`

### Docker Deployment

```bash
# Build the image
docker build -t soc-automation-bot .

# Run the container
docker run -d -p 5000:5000 --name soc-bot soc-automation-bot

# View logs
docker logs -f soc-bot
```

## 🎯 Usage

### Command Line Options

```bash
python main.py --help

Options:
  --mode {once,continuous,dashboard}  Run mode (default: continuous)
  --config CONFIG                    Configuration file path
  --no-dashboard                     Disable web dashboard
  --port PORT                        Dashboard port (default: 5000)
  --host HOST                        Dashboard host (default: 0.0.0.0)
  --debug                           Enable debug mode
```

### Run Modes

- **Continuous Mode**: `python main.py --mode continuous`
  - Runs the full pipeline continuously with auto-refresh
  - Includes web dashboard for real-time monitoring

- **Once Mode**: `python main.py --mode once` 
  - Processes alerts once and exits
  - Perfect for testing and batch processing

- **Dashboard Only**: `python main.py --mode dashboard`
  - Runs only the web dashboard
  - Useful for monitoring existing data

## 📊 Dashboard Features

The web dashboard provides:

- **📈 Real-time Metrics**: Total alerts, risk distribution, response times
- **🔍 Alert Tables**: Raw, enriched, triaged, and processed alerts
- **⚡ Auto-refresh**: Configurable refresh intervals
- **🎨 Risk Visualization**: Color-coded risk levels and status indicators
- **📱 Responsive Design**: Works on desktop, tablet, and mobile

### Dashboard Views

1. **Processed Alerts**: Final alerts with actions taken
2. **Triaged Alerts**: Risk-scored and prioritized alerts  
3. **Enriched Alerts**: Alerts with threat intelligence
4. **Raw Alerts**: Original SIEM data

## 🔧 Configuration

The bot uses `soc_config.json` for configuration:

```json
{
  "ingestion": {
    "json_file": null,
    "csv_file": null,
    "use_sample": true,
    "poll_interval": 30
  },
  "enrichment": {
    "enable_whois": true,
    "enable_abuse_db": true,
    "enable_mitre": true,
    "rate_limit": 0.1
  },
  "triage": {
    "model_type": "sklearn",
    "retrain_interval": 100,
    "confidence_threshold": 0.7
  },
  "response": {
    "enable_blocking": true,
    "enable_tickets": true,
    "enable_email": true,
    "dry_run": false
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5000,
    "auto_refresh": 10,
    "debug": false
  }
}
```

## 🤖 AI Triage Engine

The triage engine uses scikit-learn with the following features:

### Risk Factors
- **Abuse Score** (40% weight): IP reputation from threat feeds
- **Geolocation** (20% weight): High-risk countries and regions  
- **Network Context** (15% weight): External vs internal traffic
- **Port Analysis** (10% weight): High-risk service ports
- **Event Type** (10% weight): Attack pattern classification
- **Data Volume** (5% weight): Unusual data transfer sizes

### Machine Learning Model
- **Algorithm**: Random Forest Classifier
- **Features**: 11 features from enriched data (7 numeric, 4 label-encoded categorical)
- **Training**: Learns the rule-based rubric above from a fixed-seed set of 2,000 synthetic alerts. `triage()` trains it automatically when `triage_model.pkl` is missing; run `python train_model.py` to rebuild a stale model file
- **Agreement with the rubric**: 93.8% ± 0.9% on 5 × 1,000 unseen synthetic alerts (majority-class baseline 49.4%). This measures how faithfully the model reproduces the rules, not accuracy against analyst verdicts

## ⚡ Response Actions

The response engine takes automated actions based on risk levels:

### Low Risk Alerts
- ✅ **Log**: Record to security logs
- 👁️ **Monitor**: Add to watchlist

### Medium Risk Alerts  
- ✅ **Log**: Record to security logs
- 👁️ **Monitor**: Add to watchlist
- 📧 **Email Alert**: Notify security team

### High Risk Alerts
- ✅ **Log**: Record to security logs
- 👁️ **Monitor**: Add to watchlist  
- 📧 **Email Alert**: Notify security team
- 🎫 **Create Ticket**: Generate incident ticket
- 🚫 **Block IP**: Firewall rule creation

## 📁 Project Structure

```
soc-automation-bot/
├── main.py              # Main orchestrator
├── ingestion.py         # SIEM data ingestion
├── enrichment.py        # Threat intelligence enrichment
├── triage.py           # AI-powered risk assessment
├── response.py         # Automated response actions
├── dashboard.py        # Flask web dashboard
├── train_model.py      # Rebuild triage_model.pkl from the reference dataset
├── benchmark.py        # Reproducible pipeline and model benchmark
├── tests/              # Integration and model tests
├── requirements.txt    # Python dependencies
├── Dockerfile         # Container configuration
├── README.md          # This file
└── logs/              # Generated log files
    ├── soc_automation.log
    ├── email_alerts.log
    ├── action_log.json
    └── monitoring_queue.json
```

## 🔐 Security Considerations

- **Firewall Integration**: Placeholder for iptables commands (customize for your environment)
- **API Keys**: Use environment variables for threat intelligence APIs
- **Network Access**: Run in isolated network segment
- **Logging**: All actions are logged with timestamps and details
- **User Permissions**: Docker runs as non-root user

## 🚦 Monitoring & Alerting

### Key Metrics Tracked
- **MTTD**: Mean Time to Detection
- **MTTR**: Mean Time to Response  
- **Alert Volume**: Total and by risk level
- **False Positive Rate**: Model accuracy metrics
- **Response Effectiveness**: Action success rates

### Log Files Generated
- `soc_automation.log`: Main application logs
- `email_alerts.log`: Email notifications sent
- `action_log.json`: Detailed action history
- `blocked_ips.json`: IP blocking history
- `incident_tickets.json`: Generated tickets

## 🔧 Customization

### Adding Custom Alert Sources
Modify `ingestion.py` to support your SIEM:

```python
def custom_siem_connector():
    # Add your SIEM API integration here
    pass
```

### Custom Enrichment Sources
Extend `enrichment.py` with additional threat feeds:

```python
def custom_threat_feed(ip_address):
    # Add custom threat intelligence
    pass
```

### Response Actions
Add new response actions in `response.py`:

```python
def custom_response_action(alert):
    # Implement custom response logic
    pass
```

## 🐛 Troubleshooting

### Common Issues

1. **Port 5000 in use**
   ```bash
   python main.py --port 8080
   ```

2. **Permission denied for iptables**
   - Run with sudo or modify response.py for your firewall

3. **Model training errors or poor triage**
   - Rebuild the model: `python train_model.py`
   - Check feature column availability

4. **Dashboard not loading**
   - Verify Flask is running: `curl http://localhost:5000/api/metrics`
   - Check browser console for JavaScript errors

### Debug Mode
```bash
python main.py --debug
```

## 📈 Performance

Reproduce with `python benchmark.py` (add `--json` for raw numbers). It runs in a temporary
directory and takes about a minute. Figures below are from an Apple M2 with Python 3.13.

Alerts, WHOIS and AbuseIPDB data are all synthetic, so these numbers describe the pipeline's
behaviour, not detection quality on real traffic.

| Metric | Result |
|---|---|
| 50-alert batch, end to end | 0.73 s ± 0.02 over 10 runs (enrichment 0.65 s, triage 0.04 s, response 0.04 s) |
| Throughput | ~3,700 alerts/min at 500 alerts; ~3,100–3,300 at 1,000 |
| Triage model vs rule-based rubric | 93.8% ± 0.9% on 5 × 1,000 unseen alerts (majority-class baseline 49.4%) |
| Risk split, 1,000 alerts | 48.0% High / 31.1% Medium / 20.9% Low |
| High-risk alerts per 50-alert batch | 25.0 ± 3.2 over 30 runs (range 18–30) |
| MITRE ATT&CK coverage | 12 event types mapped to 19 distinct techniques |
| Failed response actions, 1,000 alerts | 0 |

- Enrichment sleeps 10 ms per alert to stand in for API calls, so it dominates runtime.
- Response time grows faster than batch size because the monitoring queue, ticket and
  blocked-IP files are read and rewritten for every alert.
- The risk split comes from the sample generator: half of its 12 source IPs are flagged as
  suspicious. High-risk alerts are ticketed and their source IP blocked, but a 1,000-alert run
  only ever blocks 6 distinct IPs.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MITRE ATT&CK**: Framework for attack pattern mapping
- **scikit-learn**: Machine learning capabilities
- **Flask**: Web dashboard framework
- **Pandas**: Data processing and analysis

---

**⚠️ Production Deployment Note**: This is a demonstration system. For production use, integrate with your actual SIEM, threat intelligence feeds, and security infrastructure. Always test in a controlled environment first.