# Graph Report - .  (2026-09-03)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 191 nodes · 343 edges · 16 communities (13 shown, 3 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.5)
- Token cost: 40,855 input · 265 output

## Graph Freshness
- Built from commit: `b381468f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- SIEM & Case Management Integrations
- SOC Bot Orchestration & CLI
- Automated Response Actions
- End-to-End Pipeline Tests
- ML Alert Triage Classifier
- Pipeline Module Summaries
- Threat Intel Alert Enrichment
- Alert Ingestion & Normalization
- Dashboard Metrics API
- Pipeline Execution & Data Refresh
- Error Handling Tests
- Security Validation Tests
- Deployment Script Output Helpers
- Test Fixtures
- Dashboard Page Rendering
- Project Docs & Graph Config

## God Nodes (most connected - your core abstractions)
1. `ingest_alerts()` - 22 edges
2. `SOCAutomationBot` - 21 edges
3. `triage()` - 20 edges
4. `enrich_alerts()` - 19 edges
5. `ResponseEngine` - 11 edges
6. `execute_actions()` - 11 edges
7. `load_data()` - 9 edges
8. `EnterpriseSOCIntegrator` - 9 edges
9. `AlertTriageClassifier` - 9 edges
10. `WazuhIntegration` - 8 edges

## Surprising Connections (you probably didn't know these)
- `SOCAutomationBot` --uses--> `EnterpriseSOCIntegrator`  [INFERRED]
  main.py → integrations.py
- `TestErrorHandling` --uses--> `SOCAutomationBot`  [INFERRED]
  tests/test_integration.py → main.py
- `TestSecurity` --uses--> `SOCAutomationBot`  [INFERRED]
  tests/test_integration.py → main.py
- `TestSOCPipeline` --uses--> `SOCAutomationBot`  [INFERRED]
  tests/test_integration.py → main.py
- `load_data()` --calls--> `enrich_alerts()`  [EXTRACTED]
  dashboard.py → enrichment.py

## Import Cycles
- None detected.

## Communities (16 total, 3 thin omitted)

### Community 0 - "SIEM & Case Management Integrations"
Cohesion: 0.08
Nodes (21): EnterpriseSOCIntegrator, main(), Map Wazuh rule levels to our severity, Integration with The Hive case management, Create a case in The Hive, Add observable to The Hive case, Map our severity to The Hive severity, Integration with Wazuh SIEM (+13 more)

### Community 1 - "SOC Bot Orchestration & CLI"
Cohesion: 0.10
Nodes (17): main(), Save current configuration to file, Load configuration from file, Run the SOC automation in continuous mode, Start the web dashboard in a separate thread, Run the pipeline once and exit, Alias for run_once method for test compatibility, Print current statistics (+9 more)

### Community 2 - "Automated Response Actions"
Cohesion: 0.19
Nodes (9): Send email notification (simulated), Create incident ticket (simulated), Block IP address (simulated firewall action), Quarantine compromised host (placeholder), Execute appropriate actions for a single alert, Log an action to the action log, Basic logging action for all alerts, Add alert to monitoring queue (+1 more)

### Community 3 - "End-to-End Pipeline Tests"
Cohesion: 0.18
Nodes (12): enrich_alerts(), Main enrichment function that adds contextual information to alerts      Args:, Test complete end-to-end workflow, Test the complete SOC automation pipeline, Test the complete pipeline from ingestion to response, Test pipeline performance meets SLA requirements, Test data quality throughout the pipeline, Test alert risk classification accuracy (+4 more)

### Community 4 - "ML Alert Triage Classifier"
Cohesion: 0.19
Nodes (7): AlertTriageClassifier, Prepare features for ML model, Train the classification model, Predict risk levels for new alerts, Save trained model to disk, Load trained model from disk, Create labeled training data based on heuristic rules

### Community 5 - "Pipeline Module Summaries"
Cohesion: 0.39
Nodes (6): Run the Flask dashboard, run_dashboard(), get_response_summary(), Generate summary of response actions, get_triage_summary(), Generate summary statistics for triaged alerts

### Community 6 - "Threat Intel Alert Enrichment"
Cohesion: 0.24
Nodes (10): enrich_single_alert(), get_abuse_score(), get_mitre_tags(), get_whois_info(), is_private_ip(), Simulate AbuseIPDB lookup - in production, use actual AbuseIPDB API, Map event type to MITRE ATT&CK techniques, Enrich a single alert with external data (+2 more)

### Community 7 - "Alert Ingestion & Normalization"
Cohesion: 0.17
Nodes (11): generate_sample_alerts(), ingest_alerts(), normalize_alerts(), Read alerts from CSV file, Normalize alert data into standardized format, Generate sample security alerts for demonstration, Main ingestion function that reads alerts from various sources     and returns a, Read alerts from JSON file (+3 more)

### Community 8 - "Dashboard Metrics API"
Cohesion: 0.25
Nodes (8): api_data(), api_metrics(), get_alert_data_for_table(), get_metrics(), Get alert data formatted for tables, API endpoint to get latest alert data and metrics, Calculate SOC metrics, API endpoint for just metrics

### Community 9 - "Pipeline Execution & Data Refresh"
Cohesion: 0.25
Nodes (7): api_refresh(), load_data(), Load and process the latest alert data, API endpoint to force data refresh, Execute the complete SOC automation pipeline, execute_actions(), Main response function that executes actions based on alert risk levels      Arg

### Community 10 - "Error Handling Tests"
Cohesion: 0.25
Nodes (5): Test error handling and resilience, Test handling of empty alert datasets, Test handling of API failures, Test handling of malformed data, TestErrorHandling

### Community 11 - "Security Validation Tests"
Cohesion: 0.33
Nodes (4): Test security-related functionality, Test IP address validation, Test security response actions, TestSecurity

### Community 12 - "Deployment Script Output Helpers"
Cohesion: 0.60
Nodes (5): print_error(), print_info(), print_success(), print_warning(), deploy.sh script

## Knowledge Gaps
- **1 isolated node(s):** `graphify`
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SOCAutomationBot` connect `SOC Bot Orchestration & CLI` to `SIEM & Case Management Integrations`, `End-to-End Pipeline Tests`, `Pipeline Module Summaries`, `Pipeline Execution & Data Refresh`, `Error Handling Tests`, `Security Validation Tests`, `Test Fixtures`?**
  _High betweenness centrality (0.195) - this node is a cross-community bridge._
- **Why does `triage()` connect `End-to-End Pipeline Tests` to `ML Alert Triage Classifier`, `Pipeline Module Summaries`, `Pipeline Execution & Data Refresh`, `Error Handling Tests`, `Test Fixtures`?**
  _High betweenness centrality (0.148) - this node is a cross-community bridge._
- **Why does `EnterpriseSOCIntegrator` connect `SIEM & Case Management Integrations` to `SOC Bot Orchestration & CLI`, `Pipeline Module Summaries`?**
  _High betweenness centrality (0.121) - this node is a cross-community bridge._
- **Are the 5 inferred relationships involving `SOCAutomationBot` (e.g. with `EnterpriseSOCIntegrator` and `TestErrorHandling`) actually correct?**
  _`SOCAutomationBot` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `SIEM & Case Management Integrations` be split into smaller, more focused modules?**
  _Cohesion score 0.07507507507507508 - nodes in this community are weakly interconnected._
- **Should `SOC Bot Orchestration & CLI` be split into smaller, more focused modules?**
  _Cohesion score 0.09852216748768473 - nodes in this community are weakly interconnected._