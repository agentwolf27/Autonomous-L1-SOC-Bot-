#!/usr/bin/env python3
"""
SOC Automation Bot - Main Runner
Level 1 Security Operations Center Automation

This module orchestrates the complete SOC automation pipeline:
1. Data Ingestion (SIEM alerts)
2. Alert Enrichment (WHOIS, AbuseIPDB, MITRE ATT&CK)
3. AI Triage (Risk scoring and classification)
4. Automated Response (Blocking, tickets, notifications)
5. Web Dashboard (Real-time monitoring)
"""

import sys
import os
import time
import logging
import threading
import signal
import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Any

# Import our SOC modules
from ingestion import ingest_alerts
from enrichment import enrich_alerts
from triage import triage, get_triage_summary
from response import execute_actions, get_response_summary
from dashboard import run_dashboard

# Import enterprise integrations
try:
    from integrations import EnterpriseSOCIntegrator, ENTERPRISE_CONFIG

    ENTERPRISE_AVAILABLE = True
except ImportError:
    ENTERPRISE_AVAILABLE = False
    print(
        "Enterprise integrations not available. Install additional dependencies for Wazuh/Hive integration."
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("soc_automation.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class SOCAutomationBot:
    def __init__(
        self, config_path: str = "soc_config.json", enterprise_mode: bool = False
    ):
        self.config = self.load_default_config()
        self.running = False
        self.dashboard_thread = None
        self.processing_stats = {
            "total_runs": 0,
            "total_alerts_processed": 0,
            "last_run_time": None,
            "errors": 0,
            "start_time": datetime.now(),
        }

        # Enterprise integrations
        self.enterprise_mode = enterprise_mode and ENTERPRISE_AVAILABLE
        if self.enterprise_mode:
            try:
                self.enterprise_integrator = EnterpriseSOCIntegrator(ENTERPRISE_CONFIG)
                self.logger.info("Enterprise integrations initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize enterprise integrations: {e}")
                self.enterprise_mode = False

    def load_default_config(self):
        """Load default configuration"""
        return {
            "ingestion": {
                "json_file": None,
                "csv_file": None,
                "use_sample": True,
                "poll_interval": 30,  # seconds
            },
            "enrichment": {
                "enable_whois": True,
                "enable_abuse_db": True,
                "enable_mitre": True,
                "rate_limit": 0.1,  # seconds between API calls
            },
            "triage": {
                "model_type": "sklearn",  # or 'llm'
                "retrain_interval": 100,  # alerts
                "confidence_threshold": 0.7,
            },
            "response": {
                "enable_blocking": True,
                "enable_tickets": True,
                "enable_email": True,
                "dry_run": False,
            },
            "dashboard": {
                "host": "0.0.0.0",
                "port": 5000,
                "auto_refresh": 10,  # seconds
                "debug": False,
            },
            "logging": {
                "level": "INFO",
                "file": "soc_automation.log",
                "max_size": "10MB",
            },
        }

    def save_config(self, filepath="soc_config.json"):
        """Save current configuration to file"""
        try:
            with open(filepath, "w") as f:
                json.dump(self.config, f, indent=2, default=str)
            logger.info(f"Configuration saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def load_config(self, filepath="soc_config.json"):
        """Load configuration from file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    self.config = json.load(f)
                logger.info(f"Configuration loaded from {filepath}")
            else:
                logger.info("No config file found, using defaults")
                self.save_config(filepath)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")

    def process_alerts_pipeline(self):
        """Execute the complete SOC automation pipeline"""
        try:
            logger.info("=" * 60)
            logger.info("Starting SOC Automation Pipeline")
            logger.info("=" * 60)

            start_time = time.time()

            # Step 1: Ingest Alerts
            if self.enterprise_mode:
                # Use enterprise sources (Wazuh, Sysmon)
                self.logger.info("Collecting alerts from enterprise sources...")
                raw_alerts = self.enterprise_integrator.collect_all_alerts()
                if not raw_alerts:
                    # Fallback to simulated data if no enterprise alerts
                    self.logger.info("No enterprise alerts found, using simulated data")
                    raw_alerts = ingest_alerts(
                        json_file=self.config["ingestion"].get("json_file"),
                        csv_file=self.config["ingestion"].get("csv_file"),
                        use_sample=self.config["ingestion"].get("use_sample", True),
                    )
            else:
                # Use simulated SIEM data
                raw_alerts = ingest_alerts(
                    json_file=self.config["ingestion"].get("json_file"),
                    csv_file=self.config["ingestion"].get("csv_file"),
                    use_sample=self.config["ingestion"].get("use_sample", True),
                )

            if raw_alerts.empty:
                logger.warning("No alerts to process")
                return None

            logger.info(f"Ingested {len(raw_alerts)} alerts")

            # Step 2: Enrich Alerts
            logger.info("Step 2: Enriching alerts...")
            enriched_alerts = enrich_alerts(raw_alerts)
            logger.info(f"Enriched {len(enriched_alerts)} alerts")

            # Step 3: Triage Alerts
            logger.info("Step 3: Triaging alerts...")
            triaged_alerts = triage(enriched_alerts)

            # Get triage summary
            triage_summary = get_triage_summary(triaged_alerts)
            logger.info(f"Triage completed: {triage_summary}")

            # Step 4: Execute Response Actions
            logger.info("Step 4: Executing response actions...")
            processed_alerts = execute_actions(triaged_alerts)

            # Enterprise integration: Create cases in The Hive for high-risk alerts
            if self.enterprise_mode:
                for _, alert in processed_alerts.iterrows():
                    if alert.get("risk_level") in ["High", "Critical"]:
                        try:
                            alert_dict = alert.to_dict()
                            case_id = self.enterprise_integrator.create_case_for_alert(
                                alert_dict
                            )
                            if case_id:
                                processed_alerts.at[alert.name, "hive_case_id"] = (
                                    case_id
                                )
                                self.logger.info(
                                    f"Created The Hive case {case_id} for alert {alert_dict['id']}"
                                )
                        except Exception as e:
                            self.logger.error(f"Failed to create The Hive case: {e}")

            # Get response summary
            response_summary = get_response_summary(processed_alerts)
            logger.info(f"Response actions completed: {response_summary}")

            # Save processed alerts
            output_file = (
                f"processed_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            processed_alerts.to_csv(output_file, index=False)
            logger.info(f"Processed alerts saved to {output_file}")

            # Update statistics
            self.processing_stats["total_runs"] += 1
            self.processing_stats["total_alerts_processed"] += len(processed_alerts)
            self.processing_stats["last_run_time"] = datetime.now()

            processing_time = time.time() - start_time
            logger.info(f"Pipeline completed in {processing_time:.2f} seconds")

            return {
                "raw_alerts": raw_alerts,
                "enriched_alerts": enriched_alerts,
                "triaged_alerts": triaged_alerts,
                "processed_alerts": processed_alerts,
                "triage_summary": triage_summary,
                "response_summary": response_summary,
                "processing_time": processing_time,
            }

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            self.processing_stats["errors"] += 1
            return None

    def run_continuous(self):
        """Run the SOC automation in continuous mode"""
        logger.info("Starting SOC Automation Bot in continuous mode")
        self.running = True

        poll_interval = self.config["ingestion"].get("poll_interval", 30)

        while self.running:
            try:
                # Process alerts
                result = self.process_alerts_pipeline()

                if result:
                    logger.info(f"Processed {len(result['processed_alerts'])} alerts")

                # Wait for next cycle
                logger.info(f"Waiting {poll_interval} seconds for next cycle...")
                for _ in range(poll_interval):
                    if not self.running:
                        break
                    time.sleep(1)

            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping...")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Continuous mode error: {e}")
                time.sleep(5)  # Brief pause before retry

    def start_dashboard(self):
        """Start the web dashboard in a separate thread"""

        def dashboard_worker():
            try:
                run_dashboard(
                    host=self.config["dashboard"].get("host", "0.0.0.0"),
                    port=self.config["dashboard"].get("port", 5000),
                    debug=self.config["dashboard"].get("debug", False),
                )
            except Exception as e:
                logger.error(f"Dashboard error: {e}")

        self.dashboard_thread = threading.Thread(target=dashboard_worker, daemon=True)
        self.dashboard_thread.start()
        logger.info(
            f"Dashboard started on http://{self.config['dashboard']['host']}:{self.config['dashboard']['port']}"
        )

    def run_once(self):
        """Run the pipeline once and exit"""
        logger.info("Running SOC Automation Pipeline once")
        result = self.process_alerts_pipeline()

        if result:
            # Print summary
            print("\n" + "=" * 60)
            print("SOC AUTOMATION SUMMARY")
            print("=" * 60)
            print(f"Total alerts processed: {len(result['processed_alerts'])}")
            print(f"Processing time: {result['processing_time']:.2f} seconds")
            print("\nTriage Summary:")
            for key, value in result["triage_summary"].items():
                print(f"  {key}: {value}")
            print("\nResponse Summary:")
            for key, value in result["response_summary"].items():
                print(f"  {key}: {value}")
            print("=" * 60)

        return result

    def print_stats(self):
        """Print current statistics"""
        uptime = datetime.now() - self.processing_stats["start_time"]

        print("\n" + "=" * 60)
        print("SOC AUTOMATION STATISTICS")
        print("=" * 60)
        print(f"Uptime: {uptime}")
        print(f"Total runs: {self.processing_stats['total_runs']}")
        print(
            f"Total alerts processed: {self.processing_stats['total_alerts_processed']}"
        )
        print(f"Last run: {self.processing_stats['last_run_time']}")
        print(f"Errors: {self.processing_stats['errors']}")
        print("=" * 60)

    def stop(self):
        """Stop the SOC automation bot"""
        logger.info("Stopping SOC Automation Bot...")
        self.running = False

        if self.dashboard_thread and self.dashboard_thread.is_alive():
            logger.info("Waiting for dashboard to stop...")
            # Dashboard will stop when main thread exits

        self.print_stats()
        logger.info("SOC Automation Bot stopped")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    if "bot" in globals():
        bot.stop()
    sys.exit(0)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Autonomous L1 SOC Bot")
    parser.add_argument(
        "--mode",
        choices=["once", "continuous", "dashboard"],
        default="once",
        help="Run mode: once, continuous, or dashboard",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Interval in seconds for continuous mode",
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port for dashboard mode"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host for dashboard mode"
    )
    parser.add_argument(
        "--enterprise",
        action="store_true",
        help="Enable enterprise integrations (Wazuh, The Hive, Sysmon)",
    )

    args = parser.parse_args()

    # Initialize the bot
    global bot
    bot = SOCAutomationBot(enterprise_mode=args.enterprise)

    # Load configuration
    bot.load_config()

    # Update config with command line args
    if args.port:
        bot.config["dashboard"]["port"] = args.port
    if args.host:
        bot.config["dashboard"]["host"] = args.host
    # Debug mode would go here if added to args

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.mode == "once":
            # Run pipeline once
            bot.run_once()

        elif args.mode == "dashboard":
            # Run only dashboard
            logger.info("Starting dashboard-only mode")
            bot.start_dashboard()

            # Keep alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        elif args.mode == "continuous":
            # Start dashboard alongside continuous processing
            bot.start_dashboard()
            time.sleep(2)  # Give dashboard time to start

            # Run continuous processing
            bot.run_continuous()

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1

    finally:
        bot.stop()

    return 0


if __name__ == "__main__":
    print(
        """
    ╔══════════════════════════════════════════════════════════════╗
    ║                  SOC AUTOMATION BOT v1.0                    ║
    ║              Level 1 Security Operations Center             ║
    ║                                                              ║
    ║  🛡️  SIEM Integration  │  🧠 AI Triage  │  ⚡ Auto Response  ║
    ║  📊 Real-time Dashboard │  🔍 Threat Intel │  📧 Notifications ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    )

    sys.exit(main())
