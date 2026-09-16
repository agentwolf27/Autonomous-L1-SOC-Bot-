# Decisions — Autonomous-L1-SOC-Bot-

Append-only. Each decision carries a reason, the alternative it beat, and a Status:
`settled` (argued and stands) · `taken` (decided by one person, contestable) · `contested`
(a challenge is open) · `open` (nobody has decided). Never edit an entry; supersede it with a
new one. Contest by appending `### Challenge — D<n> — <who>` and flipping the status.

## D1 — Train the default triage model on a fixed-seed reference set · taken · claude · 2026-09-16

When no `triage_model.pkl` exists, `triage()` trains on 2,000 synthetic alerts generated with
seed 42, not on the batch being triaged. `train_model.py` rebuilds the file on demand.

*Reason:* Training on the incoming batch gave a 50-alert run only 40 training rows, and that
model matched the rubric on 82.9% of unseen alerts; the reference set reaches 93.8% and is the
same on every clone. Committing a trained `triage_model.pkl` was rejected: it is a 1.8 MB
pickle tied to the scikit-learn version, loading a pickle from a repo can execute code, and
`*.pkl` is already gitignored.

*Revisit if:* analyst-labelled real alerts become available to train on, or the rubric in
`create_training_data` changes (existing model files are not detected as stale; rerun
`train_model.py`).
