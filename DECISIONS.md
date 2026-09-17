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

## D2 — Encode unseen categorical values as -1 instead of refitting the encoder · taken · claude · 2026-09-16

`prepare_features` looks each value up in the fitted `LabelEncoder.classes_` and encodes a
value the model never saw as `UNSEEN_CATEGORY_CODE` (-1), logging a warning. The encoder is
never refitted after training.

*Reason:* The old fallback refitted the encoder on old + new values. `LabelEncoder` sorts its
classes, so one unseen event type that sorts first ("AAA Unknown Event") shifted the code of
every known event type in a 200-alert batch, changed 5 of those 200 risk levels, and stayed in
the loaded encoder for the rest of the process. Rejected: appending new values after the
existing classes instead of re-sorting (known codes stay put, but the loaded encoder still
grows with every new value an alert source sends, and each gets a code the model was never
trained on); encoding unseen values as `len(classes_)` (same stability, but the forest then
scores them like the *last* class instead of the first, which is no less arbitrary).

*Known cost:* every split on an encoded column has its threshold at 0.5 or above, so -1 always
takes the same branch as code 0. An unseen value is scored exactly like the first trained class in sort
order: event type → "Brute Force Attack", severity → "Critical", protocol → "ICMP", country →
"CN". The rubric would instead give an unknown event type or country 0 points and an unknown
severity the Low score. Stability was the goal here; the scoring meaning is task 8.

*Revisit if:* real alerts start carrying values outside the synthetic vocabulary (the warning
shows them), or task 8 trains a dedicated unseen bucket, which would replace the -1 sentinel.

## D3 — Pin black to 24.8.0 in CI · taken · claude · 2026-09-16

CI installs `black==24.8.0`; the formatting check still runs on every Python in the matrix.

*Reason:* CI installed the latest black, and its 2026 stable style reformats the
`print("""...""")` banner in `main.py`, so every run failed at the formatting step before any
test ran. 24.8.0 is the newest black that installs on Python 3.8, the oldest matrix entry; the
code passes it, the 24.10.0 in Anaconda and the 25.1.0 in the venv. Rejected: reformatting
with black 26 (the venv's 25.1.0 would then disagree with CI); running the check once on 3.11
with black 25.1.0 (the auto-mode classifier refused removing black from the shared install
step, and the pin alone was enough).

*Revisit if:* the matrix drops Python 3.8, at which point pin CI to the same black as the venv.

## D4 — Train the model on a reserved unseen value instead of mapping unseen values to a known class · taken · claude · 2026-09-16

Supersedes D2's -1 sentinel for models trained from now on; -1 remains only for model files
saved before this change. `train()` holds out 20% of the real alerts first, then trains on the
rest plus two copies of them. Each copy has a random, non-empty subset of `event_type`,
`severity`, `protocol` and `source_whois_country` replaced by `UNSEEN_CATEGORY`
(`"__unseen__"`), and the rubric labels the copies. `prepare_features` encodes a value missing
from the fitted classes as `UNSEEN_CATEGORY`.

*Reason:* The rubric already says what an unknown value means: no points for an unknown event
type or country, and Low for an unknown severity. Labelling copies with it teaches the model
that meaning without writing it down a second time. Rubric agreement on 5 × 1,000 alerts:

| Unseen value in | -1 sentinel (D2) | Map to a neutral known class | This decision |
|---|---|---|---|
| event type | 88.3% | 94.6% | 95.9% |
| severity | 74.4% | 93.1% | 93.1% |
| protocol | 94.1% | 93.9% | 94.0% |
| country | 76.4% | 88.5% | 88.7% |
| all four | 39.8% | 70.6% | 90.6% |

Known alerts go from 93.8% to 94.0%. Rejected: mapping unseen values to a rubric-neutral
known class ("Suspicious Network Traffic", "Low", "TCP", "US"). It needs no retraining, but
it copies the rubric's meaning into a second table that has to be kept in sync, and scores
only 70.6% when all four values are unseen. Also rejected: one copy per row. Across five RNG
seeds, all four unseen scored between 84.6% and 87.5%, and on one seed the test's unseen
country was 0.8 points above its threshold. Two copies gave 88.2–88.6% across three seeds
in the same trial, and 90.6% as implemented.

*Known cost:* the country case stays the weakest. A model trained with no country at all
reaches only 90.7% on those alerts (`benchmark.py` reports both). Model files saved before
this change have no `__unseen__` class, so they keep D2's behaviour, with a warning on each
batch that holds an unseen value, until rebuilt with `train_model.py`. Nothing checks for
this when a model is loaded.

*Revisit if:* the rubric in `create_training_data` gains or loses a categorical factor, or
real alerts show unseen values clustering in one column, which might warrant extra copies
that hide only that column.
