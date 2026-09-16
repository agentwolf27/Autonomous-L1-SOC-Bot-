# Autonomous-L1-SOC-Bot-

<!-- pulse -->

## What we are building
A Python Level 1 SOC automation bot. It ingests security alerts (JSON/CSV, or synthetic sample alerts by default), enriches them with MITRE ATT&CK mapping and simulated WHOIS and AbuseIPDB lookups, triages risk with a RandomForest trained to reproduce a rule-based rubric, takes tiered response actions (log, monitor, email, ticket, IP block, all simulated as file writes), and shows the results on a Flask dashboard.

## Why
It automates repetitive L1 alert handling to reduce analyst workload in small SOCs. It is also a portfolio project, so every metric quoted about it must be reproducible from the repo.

## Done looks like
A short list of concrete, checkable outcomes. If you cannot check it, it does not belong here.
Tick one only when its VERIFY passes, not when someone says it is done.

- [x] Bot ingests and processes 50+ alerts per run with normalized data — `venv/bin/python -m pytest tests/test_integration.py -q -k "full_pipeline or data_quality"`
- [x] All tests pass with no failures — `venv/bin/python -m pytest tests -q`
- [x] Default triage model matches the rule-based rubric on at least 90% of unseen alerts — `venv/bin/python -m pytest tests/test_model.py -q`
- [x] Benchmark behind the README's Performance table runs end to end from a clean temporary directory — `venv/bin/python benchmark.py`
- [ ] Dashboard displays real-time metrics and alert summaries — somebody opens http://localhost:5000 in a browser
- [ ] Resume includes accurate, verifiable performance metrics — the user checks each figure against the README Performance table

## Out of scope
- Real WHOIS / AbuseIPDB API calls and real firewall changes; response actions stay simulated.
- Measuring detection accuracy against analyst verdicts; no labelled real alerts exist.

## Constraints
- CI tests Python 3.8–3.11 (`.github/workflows/ci.yml`), so code must stay compatible with 3.8.
- Black formatting is enforced in CI.
- `*.pkl`, `*.json`, `*.csv` and `*.log` are gitignored, so the triage model must be reproducible from code.
- Feature branches merge into `dev` by PR; only `dev` merges into `main`.
