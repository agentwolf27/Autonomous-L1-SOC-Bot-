from flask import Flask, render_template, jsonify, request
import pandas as pd
import json
import os
from datetime import datetime, timedelta
import logging
from ingestion import ingest_alerts
from enrichment import enrich_alerts
from triage import triage, get_triage_summary
from response import execute_actions, get_response_summary

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global variables to store latest data
latest_alerts_data = None
last_update = None

def load_data():
    """Load and process the latest alert data"""
    global latest_alerts_data, last_update
    
    try:
        # Ingest alerts
        raw_alerts = ingest_alerts()
        
        # Enrich alerts
        enriched_alerts = enrich_alerts(raw_alerts)
        
        # Triage alerts
        triaged_alerts = triage(enriched_alerts)
        
        # Execute response actions
        processed_alerts = execute_actions(triaged_alerts)
        
        latest_alerts_data = {
            'raw': raw_alerts,
            'enriched': enriched_alerts,
            'triaged': triaged_alerts,
            'processed': processed_alerts
        }
        
        last_update = datetime.now()
        logger.info(f"Data loaded successfully at {last_update}")
        
        return latest_alerts_data
        
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return None

def get_metrics():
    """Calculate SOC metrics"""
    if not latest_alerts_data:
        return {}
    
    processed_df = latest_alerts_data['processed']
    
    # Basic metrics
    total_alerts = len(processed_df)
    high_risk_alerts = len(processed_df[processed_df['risk_level'] == 'High'])
    medium_risk_alerts = len(processed_df[processed_df['risk_level'] == 'Medium'])
    low_risk_alerts = len(processed_df[processed_df['risk_level'] == 'Low'])
    
    # Calculate percentages
    high_risk_pct = (high_risk_alerts / total_alerts * 100) if total_alerts > 0 else 0
    
    # Response metrics
    tickets_created = len(processed_df[processed_df['actions_taken'].str.contains('create_ticket', na=False)])
    ips_blocked = len(processed_df[processed_df['actions_taken'].str.contains('block_ip', na=False)])
    emails_sent = len(processed_df[processed_df['actions_taken'].str.contains('email_alert', na=False)])
    
    # Time-based metrics (simulated)
    avg_detection_time = 5.2  # minutes
    avg_response_time = 12.8  # minutes
    
    # Risk score stats
    avg_risk_score = processed_df['risk_score'].mean() if not processed_df.empty else 0
    max_risk_score = processed_df['risk_score'].max() if not processed_df.empty else 0
    
    return {
        'total_alerts': total_alerts,
        'high_risk_alerts': high_risk_alerts,
        'medium_risk_alerts': medium_risk_alerts,
        'low_risk_alerts': low_risk_alerts,
        'high_risk_percentage': round(high_risk_pct, 1),
        'tickets_created': tickets_created,
        'ips_blocked': ips_blocked,
        'emails_sent': emails_sent,
        'avg_detection_time': avg_detection_time,
        'avg_response_time': avg_response_time,
        'avg_risk_score': round(avg_risk_score, 1),
        'max_risk_score': round(max_risk_score, 1),
        'last_update': last_update.strftime('%Y-%m-%d %H:%M:%S') if last_update else 'Never'
    }

def get_alert_data_for_table(data_type='processed', limit=100):
    """Get alert data formatted for tables"""
    if not latest_alerts_data or data_type not in latest_alerts_data:
        return []
    
    df = latest_alerts_data[data_type].copy()
    
    if df.empty:
        return []
    
    # Limit results
    df = df.head(limit)
    
    # Convert timestamps to strings
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Handle other datetime columns
    datetime_cols = ['triage_timestamp', 'action_timestamp']
    for col in datetime_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col]).dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Convert to list of dictionaries
    return df.to_dict('records')

# HTML template as string (for simplicity)
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SOC Automation Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { 
            background: rgba(255,255,255,0.95); 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { 
            color: #2c3e50; 
            text-align: center; 
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .subtitle { 
            text-align: center; 
            color: #7f8c8d; 
            font-size: 1.1em;
        }
        .metrics-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .metric-card { 
            background: rgba(255,255,255,0.95); 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .metric-card:hover { transform: translateY(-2px); }
        .metric-value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin: 10px 0;
        }
        .metric-label { 
            color: #7f8c8d; 
            font-size: 0.9em; 
            text-transform: uppercase;
        }
        .high-risk { color: #e74c3c; }
        .medium-risk { color: #f39c12; }
        .low-risk { color: #27ae60; }
        .info { color: #3498db; }
        .section { 
            background: rgba(255,255,255,0.95); 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .section h2 { 
            color: #2c3e50; 
            margin-bottom: 15px; 
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 10px;
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #ecf0f1;
        }
        th { 
            background: #f8f9fa; 
            font-weight: bold;
            color: #2c3e50;
        }
        tr:hover { background: #f8f9fa; }
        .risk-high { background: #ffebee; color: #c62828; }
        .risk-medium { background: #fff3e0; color: #ef6c00; }
        .risk-low { background: #e8f5e8; color: #2e7d32; }
        .btn { 
            background: #3498db; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer;
            font-size: 14px;
            margin: 5px;
        }
        .btn:hover { background: #2980b9; }
        .auto-refresh { 
            text-align: center; 
            margin: 20px 0;
        }
        .status-indicator { 
            display: inline-block; 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            margin-right: 5px;
        }
        .status-online { background: #27ae60; }
        .status-offline { background: #e74c3c; }
        .tabs {
            display: flex;
            border-bottom: 2px solid #ecf0f1;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 14px;
            color: #7f8c8d;
        }
        .tab.active {
            color: #3498db;
            border-bottom: 2px solid #3498db;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .table-container {
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid #ecf0f1;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SOC Automation Dashboard</h1>
            <div class="subtitle">
                <span class="status-indicator status-online"></span>
                Level 1 Security Operations Center - Real-time Monitoring & Response
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value info" id="total-alerts">0</div>
                <div class="metric-label">Total Alerts</div>
            </div>
            <div class="metric-card">
                <div class="metric-value high-risk" id="high-risk-alerts">0</div>
                <div class="metric-label">High Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value medium-risk" id="medium-risk-alerts">0</div>
                <div class="metric-label">Medium Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value low-risk" id="low-risk-alerts">0</div>
                <div class="metric-label">Low Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value info" id="tickets-created">0</div>
                <div class="metric-label">Tickets Created</div>
            </div>
            <div class="metric-card">
                <div class="metric-value high-risk" id="ips-blocked">0</div>
                <div class="metric-label">IPs Blocked</div>
            </div>
            <div class="metric-card">
                <div class="metric-value medium-risk" id="avg-risk-score">0</div>
                <div class="metric-label">Avg Risk Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value info" id="response-time">0</div>
                <div class="metric-label">Avg Response (min)</div>
            </div>
        </div>

        <div class="auto-refresh">
            <button class="btn" onclick="refreshData()">🔄 Refresh Data</button>
            <button class="btn" onclick="toggleAutoRefresh()" id="auto-refresh-btn">▶️ Start Auto-Refresh</button>
            <span id="last-update">Last Update: Never</span>
        </div>

        <div class="section">
            <h2>📊 Alert Data</h2>
            <div class="tabs">
                <button class="tab active" onclick="showTab('processed')">Processed Alerts</button>
                <button class="tab" onclick="showTab('triaged')">Triaged Alerts</button>
                <button class="tab" onclick="showTab('enriched')">Enriched Alerts</button>
                <button class="tab" onclick="showTab('raw')">Raw Alerts</button>
            </div>
            
            <div id="processed-content" class="tab-content active">
                <div class="table-container">
                    <table id="processed-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Event Type</th>
                                <th>Source IP</th>
                                <th>Risk Level</th>
                                <th>Risk Score</th>
                                <th>Actions Taken</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <div id="triaged-content" class="tab-content">
                <div class="table-container">
                    <table id="triaged-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Event Type</th>
                                <th>Source IP</th>
                                <th>Risk Level</th>
                                <th>Risk Score</th>
                                <th>Priority</th>
                                <th>Confidence</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <div id="enriched-content" class="tab-content">
                <div class="table-container">
                    <table id="enriched-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Source IP</th>
                                <th>Country</th>
                                <th>Abuse Score</th>
                                <th>MITRE Tags</th>
                                <th>Risk Factors</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <div id="raw-content" class="tab-content">
                <div class="table-container">
                    <table id="raw-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Event Type</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Severity</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;
        let isAutoRefresh = false;

        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName + '-content').classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        function updateMetrics(metrics) {
            document.getElementById('total-alerts').textContent = metrics.total_alerts || 0;
            document.getElementById('high-risk-alerts').textContent = metrics.high_risk_alerts || 0;
            document.getElementById('medium-risk-alerts').textContent = metrics.medium_risk_alerts || 0;
            document.getElementById('low-risk-alerts').textContent = metrics.low_risk_alerts || 0;
            document.getElementById('tickets-created').textContent = metrics.tickets_created || 0;
            document.getElementById('ips-blocked').textContent = metrics.ips_blocked || 0;
            document.getElementById('avg-risk-score').textContent = metrics.avg_risk_score || 0;
            document.getElementById('response-time').textContent = metrics.avg_response_time || 0;
            document.getElementById('last-update').textContent = 'Last Update: ' + (metrics.last_update || 'Never');
        }

        function updateTable(tableId, data, columns) {
            const tbody = document.querySelector('#' + tableId + ' tbody');
            tbody.innerHTML = '';
            
            data.forEach(row => {
                const tr = document.createElement('tr');
                
                // Add risk level class if applicable
                if (row.risk_level) {
                    tr.className = 'risk-' + row.risk_level.toLowerCase();
                }
                
                columns.forEach(col => {
                    const td = document.createElement('td');
                    td.textContent = row[col] || '';
                    tr.appendChild(td);
                });
                
                tbody.appendChild(tr);
            });
        }

        function refreshData() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    updateMetrics(data.metrics);
                    
                    // Update tables
                    updateTable('processed-table', data.processed, 
                        ['id', 'timestamp', 'event_type', 'source_ip', 'risk_level', 'risk_score', 'actions_taken', 'action_status']);
                    
                    updateTable('triaged-table', data.triaged, 
                        ['id', 'event_type', 'source_ip', 'risk_level', 'risk_score', 'priority', 'confidence']);
                    
                    updateTable('enriched-table', data.enriched, 
                        ['id', 'source_ip', 'source_whois_country', 'source_abuse_score', 'mitre_tags', 'risk_factors']);
                    
                    updateTable('raw-table', data.raw, 
                        ['id', 'timestamp', 'event_type', 'source_ip', 'destination_ip', 'severity', 'description']);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        }

        function toggleAutoRefresh() {
            const btn = document.getElementById('auto-refresh-btn');
            
            if (isAutoRefresh) {
                clearInterval(autoRefreshInterval);
                btn.textContent = '▶️ Start Auto-Refresh';
                isAutoRefresh = false;
            } else {
                autoRefreshInterval = setInterval(refreshData, 10000); // 10 seconds
                btn.textContent = '⏸️ Stop Auto-Refresh';
                isAutoRefresh = true;
                refreshData(); // Immediate refresh
            }
        }

        // Initial data load
        refreshData();
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Render the main dashboard"""
    return DASHBOARD_TEMPLATE

@app.route('/api/data')
def api_data():
    """API endpoint to get latest alert data and metrics"""
    try:
        # Load fresh data
        load_data()
        
        if not latest_alerts_data:
            return jsonify({'error': 'No data available'}), 500
        
        # Get metrics
        metrics = get_metrics()
        
        # Get table data
        response_data = {
            'metrics': metrics,
            'raw': get_alert_data_for_table('raw'),
            'enriched': get_alert_data_for_table('enriched'),
            'triaged': get_alert_data_for_table('triaged'),
            'processed': get_alert_data_for_table('processed')
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics')
def api_metrics():
    """API endpoint for just metrics"""
    try:
        metrics = get_metrics()
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Metrics API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh')
def api_refresh():
    """API endpoint to force data refresh"""
    try:
        load_data()
        return jsonify({'status': 'success', 'message': 'Data refreshed successfully'})
    except Exception as e:
        logger.error(f"Refresh API error: {e}")
        return jsonify({'error': str(e)}), 500

def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask dashboard"""
    logger.info(f"Starting SOC Dashboard on http://{host}:{port}")
    
    # Load initial data
    load_data()
    
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_dashboard(debug=True) 