# Tasks — Autonomous-L1-SOC-Bot-

Live task list. Every task has an owner and a VERIFY condition. A task is done when the
VERIFY passes, not when someone says it is.

**VERIFY is a command, not a verdict.** Write what should be run, in backticks: `` `npm test` exits 0 ``.
`/verify` runs the first backticked command and reports what happened. If a task genuinely
cannot be checked by a command, say so in plain words with **no backticks** — *reviewed by eye* —
so it is counted as uncheckable rather than quietly counted as passed.

## In progress

| # | Task | Owner | VERIFY |
|---|------|-------|--------|
| 4 | Review and merge the PR from feat/benchmark-reference-model into dev | user | the PR shows as merged on GitHub |
| 7 | Review and merge the PR from fix/unseen-category-encoding into dev (stacked on the task 4 PR; rebase onto dev after that merges) | user | the PR shows as merged on GitHub |

## Queued

| # | Task | Owner | VERIFY |
|---|------|-------|--------|
| 5 | Run CI on pushes and PRs to dev (ci.yml only triggers for main and develop) | user | `grep -qE "[[ ,]dev[] ,]" .github/workflows/ci.yml` exits 0 |
| 8 | Give unseen categorical values a rubric-neutral meaning: the `-1` sentinel is scored like the first class in sort order (an unseen severity like "Critical", an unseen country like "CN"), e.g. by training on a dedicated unseen bucket labelled by the rubric (see D2) | claude | `venv/bin/python -m pytest tests -q -k unseen_category_scored_like_rubric` exits 0 |

## Done

| # | Task | Owner | VERIFY | Completed |
|---|------|-------|--------|-----------|
| 1 | Add reproducible benchmark (`benchmark.py`) | claude | `venv/bin/python benchmark.py` exits 0 | 2026-09-16 |
| 2 | Train the default triage model on a fixed-seed 2,000-alert reference set; add `train_model.py` | claude | `venv/bin/python -m pytest tests/test_model.py -q` exits 0 | 2026-09-16 |
| 3 | Replace unmeasured README accuracy and performance figures with benchmark results | claude | `grep -q "93.8% ± 0.9%" README.md` exits 0 | 2026-09-16 |
| 6 | Stop `prepare_features` re-fitting a LabelEncoder on unseen categories, which can shift the codes of known ones; add a test named for unseen_category | claude | `venv/bin/python -m pytest tests -q -k unseen_category` exits 0 | 2026-09-16 |
