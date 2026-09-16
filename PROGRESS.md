# Progress — Autonomous-L1-SOC-Bot-

Append-only. Newest entries at the bottom. Never rewrite history — a correction is a new entry
naming what it corrects.

Format: `## YYYY-MM-DD — <who>`, what happened, and `Evidence:` the command and its real result
(or `Evidence: none — <why>`).

## 2026-09-16 — claude

Checked the portfolio figure "24 of 50 alerts (48%)". It appears nowhere in the code or docs.
It matches the mean High-risk count across the eight saved runs from 2025-06-09 (23.75 of 50,
47.5%), and one of those runs had exactly 24 priority-1 alerts. Alerts, WHOIS and AbuseIPDB
values are all simulated and 6 of the generator's 12 IPs are hard-coded as suspicious, so the
share describes the sample generator, not detection performance.

Evidence: tally of the untracked `processed_alerts_20250609_*.csv` files — High counts 20, 23,
23, 21, 29, 26, 23, 25 of 50.

## 2026-09-16 — claude

`triage_model.pkl` is gitignored, so a fresh clone trained its model on the first 50-alert
batch (40 training rows after the split). The model file in the main checkout matched the
rubric on 82.9% of unseen alerts. `triage()` now trains on a fixed-seed 2,000-alert reference
set when no model file exists (D1); added `train_model.py`, `benchmark.py` and
`tests/test_model.py`, and replaced the README's unmeasured accuracy (85–90%) and performance
figures. Retrained the main checkout's `triage_model.pkl`; the old copy (sha256 21e0b20f…) was
backed up to the session scratchpad only. Code on `chore/graphify-setup` still loads the new
file and predicts all three risk levels.

The auto-generated PLAN.md had three outcomes ticked whose VERIFY commands pointed at paths
that do not exist (`benchmark/`, `bench/benchmark.py`, `src/`) and used pipes and `&&`.
Rewrote those VERIFYs and cleared the ticks; four were re-ticked after their commands passed.

Evidence: `venv/bin/python -m pytest tests -q` — 15 passed. `venv/bin/python benchmark.py` —
exit 0; local model before retraining 82.9% ± 1.4%, after 93.8% ± 0.9% (majority-class
baseline 49.4%); 50-alert batch 0.73 s ± 0.03; 3,686 alerts/min at 500. Setting
REFERENCE_TRAINING_ALERTS to 50 on a scratch copy makes `tests/test_model.py` fail with
0.83 < 0.9, so the test catches a weak model.

## 2026-09-16 — claude

`benchmark.py` printed a pandas FutureWarning per prediction to stderr (fillna downcasting
object columns in `prepare_features`). Added `infer_objects()` before that `fillna`. Feature
matrices and predictions are identical before and after on the pipeline's object-dtype
enrichment, the typed reference dataset and malformed input, and the warning is gone.

Evidence: `venv/bin/python -m pytest tests -q` — 15 passed, 0 warnings (previously 8).
`venv/bin/python benchmark.py` — exit 0, 0 bytes on stderr, model and outcome figures
unchanged (93.8% ± 0.9%; High 48.0%).
