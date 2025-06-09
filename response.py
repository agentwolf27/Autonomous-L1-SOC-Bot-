import pandas as pd
import logging
import subprocess
import json
import os
from datetime import datetime
from typing import Dict, List
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ResponseEngine:
    def __init__(self):
        self.blocked_ips = set()
        self.action_log = []
        
        # Action mapping based on risk levels
        self.action_mapping = {
            'Low': ['log', 'monitor'],
            'Medium': ['log', 'monitor', 'email_alert'],
            'High': ['log', 'monitor', 'email_alert', 'create_ticket', 'block_ip']
        }
        
        # Email configuration (placeholder)
        self.email_config = {
            'smtp_server': 'localhost',
            'smtp_port': 587,
            'username': 'soc@company.com',
            'password': 'password',
            'to_addresses': ['security-team@company.com', 'soc-manager@company.com']
        }
    
    def log_action(self, alert_id, action, details, status='Success'):
        """Log an action to the action log"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert_id,
            'action': action,
            'details': details,
            'status': status
        }
        self.action_log.append(log_entry)
        logger.info(f"Action logged: {action} for alert {alert_id} - {status}")
    
    def log_alert(self, alert):
        """Basic logging action for all alerts"""
        alert_info = {
            'id': alert['id'],
            'event_type': alert['event_type'],
            'source_ip': alert['source_ip'],
            'risk_level': alert['risk_level'],
            'risk_score': alert['risk_score']
        }
        
        # Write to log file
        log_file = 'soc_alerts.log'
        with open(log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {json.dumps(alert_info)}\n")
        
        self.log_action(alert['id'], 'log', f"Alert logged to {log_file}")
        return True
    
    def monitor_alert(self, alert):
        """Add alert to monitoring queue"""
        monitoring_file = 'monitoring_queue.json'
        
        monitoring_entry = {
            'alert_id': alert['id'],
            'source_ip': alert['source_ip'],
            'event_type': alert['event_type'],
            'risk_level': alert['risk_level'],
            'timestamp': alert['timestamp'].isoformat() if hasattr(alert['timestamp'], 'isoformat') else str(alert['timestamp']),
            'monitoring_start': datetime.now().isoformat()
        }
        
        # Load existing monitoring queue
        monitoring_queue = []
        if os.path.exists(monitoring_file):
            try:
                with open(monitoring_file, 'r') as f:
                    monitoring_queue = json.load(f)
            except:
                monitoring_queue = []
        
        # Add new entry
        monitoring_queue.append(monitoring_entry)
        
        # Save updated queue
        with open(monitoring_file, 'w') as f:
            json.dump(monitoring_queue, f, indent=2)
        
        self.log_action(alert['id'], 'monitor', f"Alert added to monitoring queue")
        return True
    
    def send_email_alert(self, alert):
        """Send email notification (simulated)"""
        try:
            # Simulate email sending (replace with actual SMTP in production)
            subject = f"SOC Alert: {alert['event_type']} - {alert['risk_level']} Risk"
            
            body = f"""
            Security Alert Notification
            
            Alert ID: {alert['id']}
            Event Type: {alert['event_type']}
            Risk Level: {alert['risk_level']}
            Risk Score: {alert['risk_score']}
            Source IP: {alert['source_ip']}
            Destination IP: {alert['destination_ip']}
            Timestamp: {alert['timestamp']}
            
            Description: {alert['description']}
            
            Risk Factors: {alert.get('risk_factors', 'None')}
            MITRE ATT&CK: {alert.get('mitre_tags', 'None')}
            
            Please investigate this alert immediately.
            
            SOC Automation System
            """
            
            # For demonstration, write to file instead of sending email
            email_file = 'email_alerts.log'
            with open(email_file, 'a') as f:
                f.write(f"\n{'='*50}\n")
                f.write(f"TO: {', '.join(self.email_config['to_addresses'])}\n")
                f.write(f"SUBJECT: {subject}\n")
                f.write(f"TIMESTAMP: {datetime.now().isoformat()}\n")
                f.write(f"\n{body}\n")
            
            self.log_action(alert['id'], 'email_alert', f"Email notification sent to security team")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            self.log_action(alert['id'], 'email_alert', f"Failed to send email: {e}", 'Failed')
            return False
    
    def create_ticket(self, alert):
        """Create incident ticket (simulated)"""
        try:
            ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{alert['id']}"
            
            ticket_data = {
                'ticket_id': ticket_id,
                'alert_id': alert['id'],
                'title': f"{alert['event_type']} - {alert['source_ip']}",
                'description': alert['description'],
                'priority': alert.get('priority', 3),
                'risk_level': alert['risk_level'],
                'risk_score': alert['risk_score'],
                'source_ip': alert['source_ip'],
                'destination_ip': alert['destination_ip'],
                'created_timestamp': datetime.now().isoformat(),
                'status': 'Open',
                'assigned_to': 'SOC Team',
                'mitre_tags': alert.get('mitre_tags', ''),
                'risk_factors': alert.get('risk_factors', '')
            }
            
            # Save ticket to file (simulating ticket system)
            tickets_file = 'incident_tickets.json'
            tickets = []
            
            if os.path.exists(tickets_file):
                try:
                    with open(tickets_file, 'r') as f:
                        tickets = json.load(f)
                except:
                    tickets = []
            
            tickets.append(ticket_data)
            
            with open(tickets_file, 'w') as f:
                json.dump(tickets, f, indent=2)
            
            self.log_action(alert['id'], 'create_ticket', f"Incident ticket {ticket_id} created")
            return ticket_id
            
        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")
            self.log_action(alert['id'], 'create_ticket', f"Failed to create ticket: {e}", 'Failed')
            return None
    
    def block_ip(self, alert):
        """Block IP address (simulated firewall action)"""
        try:
            source_ip = alert['source_ip']
            
            # Skip blocking private IPs
            if source_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3', '127.')):
                self.log_action(alert['id'], 'block_ip', f"Skipping block for private IP {source_ip}")
                return False
            
            # Skip if already blocked
            if source_ip in self.blocked_ips:
                self.log_action(alert['id'], 'block_ip', f"IP {source_ip} already blocked")
                return True
            
            # Simulate firewall block (replace with actual firewall commands in production)
            # Example iptables command (commented out for safety):
            # subprocess.run(['iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'])
            
            # For demonstration, just log the action
            block_rule = f"iptables -A INPUT -s {source_ip} -j DROP"
            
            # Save blocked IPs to file
            blocked_ips_file = 'blocked_ips.json'
            blocked_ips_data = []
            
            if os.path.exists(blocked_ips_file):
                try:
                    with open(blocked_ips_file, 'r') as f:
                        blocked_ips_data = json.load(f)
                except:
                    blocked_ips_data = []
            
            block_entry = {
                'ip': source_ip,
                'alert_id': alert['id'],
                'blocked_timestamp': datetime.now().isoformat(),
                'rule': block_rule,
                'reason': f"{alert['event_type']} - Risk Level: {alert['risk_level']}"
            }
            
            blocked_ips_data.append(block_entry)
            
            with open(blocked_ips_file, 'w') as f:
                json.dump(blocked_ips_data, f, indent=2)
            
            self.blocked_ips.add(source_ip)
            
            self.log_action(alert['id'], 'block_ip', f"IP {source_ip} blocked via firewall rule")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            self.log_action(alert['id'], 'block_ip', f"Failed to block IP {source_ip}: {e}", 'Failed')
            return False
    
    def quarantine_host(self, alert):
        """Quarantine compromised host (placeholder)"""
        try:
            host_ip = alert['destination_ip']
            
            quarantine_data = {
                'host_ip': host_ip,
                'alert_id': alert['id'],
                'quarantine_timestamp': datetime.now().isoformat(),
                'reason': f"{alert['event_type']} - {alert['description']}"
            }
            
            quarantine_file = 'quarantined_hosts.json'
            quarantined_hosts = []
            
            if os.path.exists(quarantine_file):
                try:
                    with open(quarantine_file, 'r') as f:
                        quarantined_hosts = json.load(f)
                except:
                    quarantined_hosts = []
            
            quarantined_hosts.append(quarantine_data)
            
            with open(quarantine_file, 'w') as f:
                json.dump(quarantined_hosts, f, indent=2)
            
            self.log_action(alert['id'], 'quarantine', f"Host {host_ip} quarantined")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine host: {e}")
            self.log_action(alert['id'], 'quarantine', f"Failed to quarantine host: {e}", 'Failed')
            return False
    
    def execute_actions_for_alert(self, alert):
        """Execute appropriate actions for a single alert"""
        risk_level = alert['risk_level']
        actions = self.action_mapping.get(risk_level, ['log'])
        
        executed_actions = []
        
        for action in actions:
            try:
                if action == 'log':
                    success = self.log_alert(alert)
                elif action == 'monitor':
                    success = self.monitor_alert(alert)
                elif action == 'email_alert':
                    success = self.send_email_alert(alert)
                elif action == 'create_ticket':
                    ticket_id = self.create_ticket(alert)
                    success = ticket_id is not None
                elif action == 'block_ip':
                    success = self.block_ip(alert)
                elif action == 'quarantine':
                    success = self.quarantine_host(alert)
                else:
                    logger.warning(f"Unknown action: {action}")
                    continue
                
                if success:
                    executed_actions.append(action)
                
            except Exception as e:
                logger.error(f"Failed to execute action {action} for alert {alert['id']}: {e}")
        
        return executed_actions

def execute_actions(triaged_df):
    """
    Main response function that executes actions based on alert risk levels
    
    Args:
        triaged_df: DataFrame with triaged alerts containing risk_level column
        
    Returns:
        DataFrame with added action and action_timestamp columns
    """
    logger.info(f"Starting response actions for {len(triaged_df)} alerts")
    
    response_engine = ResponseEngine()
    
    # Create result DataFrame
    response_df = triaged_df.copy()
    
    # Initialize action columns
    response_df['actions_taken'] = ''
    response_df['action_timestamp'] = datetime.now()
    response_df['action_status'] = ''
    
    # Process each alert
    for idx, alert in response_df.iterrows():
        try:
            # Execute actions for this alert
            executed_actions = response_engine.execute_actions_for_alert(alert)
            
            # Update DataFrame
            response_df.at[idx, 'actions_taken'] = ', '.join(executed_actions)
            response_df.at[idx, 'action_timestamp'] = datetime.now()
            response_df.at[idx, 'action_status'] = 'Completed' if executed_actions else 'Failed'
            
        except Exception as e:
            logger.error(f"Failed to process actions for alert {alert.get('id', idx)}: {e}")
            response_df.at[idx, 'actions_taken'] = 'Error'
            response_df.at[idx, 'action_status'] = 'Failed'
    
    # Log summary
    action_summary = response_df['action_status'].value_counts()
    logger.info(f"Response actions completed. Status summary: {action_summary.to_dict()}")
    
    # Save action log to file
    with open('action_log.json', 'w') as f:
        json.dump(response_engine.action_log, f, indent=2)
    
    return response_df

def get_response_summary(df):
    """Generate summary of response actions"""
    summary = {
        'total_alerts_processed': len(df),
        'successful_actions': len(df[df['action_status'] == 'Completed']),
        'failed_actions': len(df[df['action_status'] == 'Failed']),
        'ips_blocked': len(df[df['actions_taken'].str.contains('block_ip', na=False)]),
        'tickets_created': len(df[df['actions_taken'].str.contains('create_ticket', na=False)]),
        'emails_sent': len(df[df['actions_taken'].str.contains('email_alert', na=False)])
    }
    return summary

if __name__ == "__main__":
    # Test response engine with sample data
    from ingestion import ingest_alerts
    from enrichment import enrich_alerts
    from triage import triage
    
    # Get sample alerts and process them
    alerts_df = ingest_alerts()
    enriched_df = enrich_alerts(alerts_df)
    triaged_df = triage(enriched_df)
    
    # Execute response actions
    response_df = execute_actions(triaged_df)
    
    print(f"Processed {len(response_df)} alerts")
    print("\nAction Status Distribution:")
    print(response_df['action_status'].value_counts())
    
    print("\nActions Taken Summary:")
    actions_summary = response_df['actions_taken'].value_counts()
    print(actions_summary.head(10))
    
    # Get response summary
    summary = get_response_summary(response_df)
    print(f"\nResponse Summary: {summary}") 