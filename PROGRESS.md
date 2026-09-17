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

## 2026-09-16 — claude

Task 6. `prepare_features` refitted a `LabelEncoder` whenever a batch held a categorical value
it had not seen. The encoder re-sorts on refit, so a value that sorts first shifts the code of
every known category. Reproduced on `fix/unseen-category-encoding` (stacked on the
feat/benchmark-reference-model PR) before changing anything: one alert with event type
"AAA Unknown Event" added to 200 known alerts shifted the event-type code on 200 of 200,
changed 5 of 200 risk levels and 97 of 200 risk scores, and left the new class in the encoder.

`prepare_features` now looks codes up in the fitted `classes_` and encodes unseen values as
`UNSEEN_CATEGORY_CODE` (-1) with a warning; the encoder is never refitted after training (D2).
Added `test_unseen_category_leaves_known_codes_and_predictions_unchanged`. Also found that the
forest scores -1 exactly like the first class in sort order (event type "Brute Force Attack",
severity "Critical", protocol "ICMP", country "CN"; levels and scores identical on 500
alerts), which does not match the rubric: queued as task 8.

This worktree has no `venv/`, so every command below ran from the worktree root with the main
checkout's interpreter (`/Users/vish/Projects/Autonomous-L1-SOC-Bot-/venv/bin/python`).
`graphify-out/` is not refreshed here, for the same reason as the benchmark PR; run
`graphify update .` in the main checkout after merging.

Evidence: `venv/bin/python -m pytest tests -q -k unseen_category` — before the fix
"15 deselected", exit 5; after, "1 passed, 15 deselected", exit 0. The same test against the
pre-fix `triage.py` (plus the constant) fails with `assert np.int64(0) == -1`; with that assert
removed it fails on `event_type_encoded` values being 100.0% different, and with the feature
checks also removed it fails on risk levels (5 / 200 mismatched).
`venv/bin/python -m pytest tests -q` — 16 passed, exit 0. `black --check .` — 11 files
unchanged. flake8 is not installed in the venv and was not run.
`venv/bin/python benchmark.py` — exit 0, 0 bytes on stderr. Triage model vs rubric 93.8% ±
0.9% (baseline 49.4%), unchanged; `--json` before and after the fix is identical for every
model and outcome figure (High 480 / Medium 311 / Low 209, pipeline agreement 93.4%, High per
50 25.0 ± 3.2). Timings on the final run: 50-alert batch 0.70 s ± 0.02, 3,858 alerts/min at
500, 3,415 at 1,000, slightly faster than the README's 0.73 s, ~3,700 and 3,100–3,300. Runtime
is dominated by enrichment's simulated delay and the triage stage took 0.03 s (README 0.04 s),
so this is run-to-run variation, not this change; the README Performance table is unchanged.

## 2026-09-16 — claude

Merged #3, #4 and #5 into dev with rebase merges (the user approved #4–#6 explicitly after the
auto-mode classifier blocked an unapproved merge). #4's first CI run failed at black: CI
installed the latest black, whose new style reformats `main.py`. Pinned `black==24.8.0` (D3),
rebased #4 onto dev, then merged it; rebased #5 onto the new dev (git dropped its duplicate of
the #3 commit) and merged it after its CI passed. After each merge the dev tree was identical to
the tree CI tested. No branches were deleted.

Evidence: CI run 35179695001 (#4 at 1a67363) and run 35180093830 (#5 at 380be20): test 3.8,
3.9, 3.10 and 3.11, security-scan and docker all success. `gh pr view` shows #3, #4 and #5
MERGED. On dev at aa7715c: `venv/bin/python -m pytest tests -q` — 16 passed;
`venv/bin/python -m pytest tests -q -k unseen_category` — 1 passed;
`grep -qE "[[ ,]dev[] ,]" .github/workflows/ci.yml` — exit 0; `venv/bin/python benchmark.py` —
exit 0, 93.8% ± 0.9%. Ticked the CI-on-dev and unseen-category outcomes in PLAN.md.

## 2026-09-16 — claude

Task 8. On dev, the -1 sentinel (D2) matched the rubric on 88.3% of alerts with an unseen
event type, 74.4% with an unseen severity, 76.4% with an unseen country and 39.8% with all four
unseen (5 × 1,000 alerts, benchmark seeds). Compared two fixes on scratch copies before
changing anything: mapping unseen values to a rubric-neutral known class, and training on
rubric-labelled copies with a reserved `__unseen__` value. The copies won, especially with all
four unseen (D4). Chose the variant and copy count on separate seeds (2001–2005), then checked
five RNG seeds: one copy per row was too sensitive to which values were hidden, so training
uses two.

`train()` now holds out 20% of the real alerts before adding the copies, so the holdout score
is measured on real rows only. `prepare_features` encodes unseen values as `__unseen__`, or as
-1 with a warning for model files saved before this change. `benchmark.py` adds a row for
unseen categories, including a model trained with no country (90.7%), the best case for an
unseen country. README: model agreement 93.8% → 94.0% ± 0.9%, risk split 31.1/20.9 →
31.3/20.7 Medium/Low, and a new unseen-categories row. Correction to task 3: its VERIFY
grepped for the old "93.8% ± 0.9%", so it now greps for "94.0% ± 0.9%". Added the PLAN outcome
for task 8 unticked; the hook ran its VERIFY in the main checkout (dev), where the test does
not exist yet, so tick it once this merges. The main checkout's `triage_model.pkl` predates
`__unseen__` (task 10).

As before, commands ran from the worktree with the main checkout's interpreter, and
`graphify-out/` was not refreshed.

Evidence: `venv/bin/python -m pytest tests -q -k unseen_category_scored_like_rubric` — on dev
(e73d103, main checkout) "16 deselected", exit 5; on this branch "5 passed, 18 deselected",
exit 0. The new tests against dev's `triage.py` (plus the constant): 6 failed, 4 passed
(the rubric test at 0.879, 0.756, 0.78 and 0.41; the protocol case and the -1 fallback test
pass on both). `venv/bin/python -m pytest tests -q -k unseen_category` — 8 passed.
`venv/bin/python -m pytest tests -q` — 23 passed. `black --check .` — clean with 25.1.0
(venv) and with 24.10.0 `--target-version py38` (Anaconda); Anaconda flake8 7.1.1 with CI's
`--select=E9,F63,F7,F82` — 0.
`venv/bin/python benchmark.py` — exit 0, 0 bytes on stderr. Agreement 94.0% ± 0.9% (was
93.8% ± 0.9% on the same seeds); unseen event type 95.9%, severity 93.1%, protocol 94.0%,
country 88.7%, all four 90.6%; High 480 / Medium 313 / Low 207 (was 311 / 209); pipeline
agreement 93.2% (was 93.4%); High per 50 unchanged at 25.0 ± 3.2. The 1,000-alert run has no
values missing from the reference set, so its 2 alerts moved from Low to Medium come from the
retrained model, not from unseen values. Timings across two runs of the final code: 50-alert batch 0.69–0.76 s, 3,347–3,742
alerts/min at 500, 3,061–3,208 at 1,000, triage 0.03 s both times. The spread is in
enrichment's simulated delay and the response file writes, so the README timings are
unchanged. `grep -qa __unseen__ triage_model.pkl` — exit 0 on a model trained by this branch,
exit 1 on the main checkout's current file.
