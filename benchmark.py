#!/usr/bin/env python3
"""
Reproducible benchmark for the SOC automation pipeline.

Alerts, WHOIS and AbuseIPDB results are all simulated, so these numbers describe how the
pipeline behaves on synthetic data, not detection performance on real traffic. The run
happens in a temporary directory, so the repo's runtime files and model are never touched.

Usage: python benchmark.py [--json]
"""

import argparse
import json
import logging
import os
import random
import statistics
import tempfile
import time

import pandas as pd

from enrichment import MITRE_ATTACK_MAPPING, enrich_alerts
from ingestion import generate_sample_alerts, normalize_alerts
from response import ResponseEngine, execute_actions
from triage import (
    REFERENCE_TRAINING_ALERTS,
    AlertTriageClassifier,
    build_reference_dataset,
    train_reference_model,
    triage,
)

REPO_MODEL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "triage_model.pkl"
)
RUNTIME_FILES = [
    "action_log.json",
    "blocked_ips.json",
    "email_alerts.log",
    "incident_tickets.json",
    "monitoring_queue.json",
    "soc_alerts.log",
]
EVAL_SEEDS = [1001, 1002, 1003, 1004, 1005]
# Categorical columns replaced by a value the model never saw, per unseen-category scenario
UNSEEN_VALUE = "Never Seen Value"
UNSEEN_SCENARIOS = {
    "event type": ["event_type"],
    "severity": ["severity"],
    "protocol": ["protocol"],
    "country": ["source_whois_country"],
    "all four": ["event_type", "severity", "protocol", "source_whois_country"],
}


def seeded_alerts(num_alerts, seed):
    """Same steps as ingest_alerts, with a fixed seed and batch size"""
    random.seed(seed)
    df = pd.DataFrame(normalize_alerts(generate_sample_alerts(num_alerts)))
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def replace_categories(df, columns):
    """Give every alert the same value in these categorical columns"""
    return df.assign(**{col: UNSEEN_VALUE for col in columns})


def run_pipeline(num_alerts, seed):
    """Run ingest -> enrich -> triage -> respond from a clean state, timing each stage"""
    for name in RUNTIME_FILES:
        if os.path.exists(name):
            os.remove(name)

    t0 = time.perf_counter()
    raw = seeded_alerts(num_alerts, seed)
    t1 = time.perf_counter()
    enriched = enrich_alerts(raw)
    t2 = time.perf_counter()
    triaged = triage(enriched)
    t3 = time.perf_counter()
    processed = execute_actions(triaged)
    t4 = time.perf_counter()

    timings = {
        "ingest": t1 - t0,
        "enrich": t2 - t1,
        "triage": t3 - t2,
        "respond": t4 - t3,
        "total": t4 - t0,
    }
    return processed, timings


def outcomes(processed):
    actions = processed["actions_taken"].fillna("")
    blocked_ips = set()
    if os.path.exists("blocked_ips.json"):
        with open("blocked_ips.json") as f:
            blocked_ips = {entry["ip"] for entry in json.load(f)}
    return {
        "alerts": len(processed),
        "high": int((processed["risk_level"] == "High").sum()),
        "medium": int((processed["risk_level"] == "Medium").sum()),
        "low": int((processed["risk_level"] == "Low").sum()),
        "ticketed": int(actions.str.contains("create_ticket").sum()),
        "analyst_notified": int(actions.str.contains("email_alert").sum()),
        "closed_without_notification": int(
            (~actions.str.contains("email_alert|create_ticket")).sum()
        ),
        "failed_actions": int((processed["action_status"] == "Failed").sum()),
        "distinct_ips_blocked": len(blocked_ips),
    }


def mean_sd(values):
    return {
        "mean": round(statistics.mean(values), 3),
        "sd": round(statistics.stdev(values), 3),
    }


def run_benchmark():
    results = {}

    techniques = {
        t.split(" - ")[0] for tags in MITRE_ATTACK_MAPPING.values() for t in tags
    }
    results["scope"] = {
        "event_types_mapped": len(MITRE_ATTACK_MAPPING),
        "distinct_mitre_techniques": len(techniques),
        "response_actions_by_tier": ResponseEngine().action_mapping,
    }

    # Train the default model up front so pipeline timings exclude the one-off training
    reference = train_reference_model()

    runs = [run_pipeline(50, seed)[1] for seed in range(10)]
    results["latency_50_alerts_10_runs_s"] = {
        stage: mean_sd([r[stage] for r in runs]) for stage in runs[0]
    }

    for size in (500, 1000):
        processed, timings = run_pipeline(size, size)
        results[f"batch_{size}"] = {
            "seconds": {k: round(v, 2) for k, v in timings.items()},
            "alerts_per_minute": round(size / timings["total"] * 60),
        }
    results["outcomes_1000_alerts"] = outcomes(processed)
    # The pipeline's own triage decisions on that batch, against the rubric
    rubric = reference.create_training_data(processed)["risk_level"].astype(str)
    results["pipeline_rubric_agreement_1000_alerts"] = round(
        float(rubric.eq(processed["risk_level"]).mean()), 3
    )

    high_counts = [
        outcomes(run_pipeline(50, 100 + seed)[0])["high"] for seed in range(30)
    ]
    results["high_risk_per_50_alerts_30_runs"] = {
        **mean_sd(high_counts),
        "min": min(high_counts),
        "max": max(high_counts),
    }

    eval_sets = [build_reference_dataset(1000, seed) for seed in EVAL_SEEDS]
    expected = [
        reference.create_training_data(df)["risk_level"].astype(str) for df in eval_sets
    ]
    majority = [e.value_counts(normalize=True).max() for e in expected]
    model = {
        "trained_on_alerts": REFERENCE_TRAINING_ALERTS,
        "reference_model_agreement_5x1000_unseen": mean_sd(
            [reference.rubric_agreement(df) for df in eval_sets]
        ),
        "majority_class_baseline": round(statistics.mean(majority), 3),
        "reference_model_agreement_5x1000_unseen_categories": {
            name: mean_sd(
                [
                    reference.rubric_agreement(replace_categories(df, columns))
                    for df in eval_sets
                ]
            )
            for name, columns in UNSEEN_SCENARIOS.items()
        },
    }
    # Best case for an unseen country: the same training with no country to learn from
    country = UNSEEN_SCENARIOS["country"]
    no_country = AlertTriageClassifier().train(
        replace_categories(build_reference_dataset(), country)
    )
    model["no_country_model_agreement_5x1000_unseen_country"] = mean_sd(
        [
            no_country.rubric_agreement(replace_categories(df, country))
            for df in eval_sets
        ]
    )
    local = AlertTriageClassifier()
    if local.load_model(REPO_MODEL):
        model["repo_triage_model_pkl_agreement_5x1000_unseen"] = mean_sd(
            [local.rubric_agreement(df) for df in eval_sets]
        )
    results["model"] = model

    return results


def pct(part, whole):
    return f"{part} ({part / whole:.1%})"


def to_markdown(r):
    lat = r["latency_50_alerts_10_runs_s"]
    b500, b1000 = r["batch_500"], r["batch_1000"]
    o = r["outcomes_1000_alerts"]
    n = o["alerts"]
    high = r["high_risk_per_50_alerts_30_runs"]
    m = r["model"]
    agree = m["reference_model_agreement_5x1000_unseen"]
    unseen = m["reference_model_agreement_5x1000_unseen_categories"]
    no_country = m["no_country_model_agreement_5x1000_unseen_country"]
    rows = [
        (
            "MITRE ATT&CK coverage",
            f"{r['scope']['event_types_mapped']} event types -> "
            f"{r['scope']['distinct_mitre_techniques']} distinct techniques",
        ),
        (
            "50-alert batch, end to end (10 runs)",
            f"{lat['total']['mean']:.2f} s ± {lat['total']['sd']:.2f} "
            f"(enrich {lat['enrich']['mean']:.2f} s, triage {lat['triage']['mean']:.2f} s, "
            f"respond {lat['respond']['mean']:.2f} s)",
        ),
        (
            "Throughput, 500-alert batch",
            f"{b500['alerts_per_minute']:,} alerts/min ({b500['seconds']['total']} s)",
        ),
        (
            "Throughput, 1,000-alert batch",
            f"{b1000['alerts_per_minute']:,} alerts/min ({b1000['seconds']['total']} s)",
        ),
        (
            "Risk split, 1,000 alerts",
            f"High {pct(o['high'], n)} / Medium {pct(o['medium'], n)} / Low {pct(o['low'], n)}",
        ),
        ("Ticketed + source IP blocked, 1,000 alerts", pct(o["ticketed"], n)),
        ("Analyst emailed, 1,000 alerts", pct(o["analyst_notified"], n)),
        (
            "Closed with log + monitor only, 1,000 alerts",
            pct(o["closed_without_notification"], n),
        ),
        ("Distinct IPs blocked, 1,000 alerts", str(o["distinct_ips_blocked"])),
        ("Failed response actions, 1,000 alerts", str(o["failed_actions"])),
        (
            "High-risk alerts per 50 (30 runs)",
            f"{high['mean']:.1f} ± {high['sd']:.1f} (range {high['min']}-{high['max']})",
        ),
        (
            f"Triage model vs rubric, 5 x 1,000 unseen alerts "
            f"(trained on {m['trained_on_alerts']:,})",
            f"{agree['mean']:.1%} ± {agree['sd']:.1%} "
            f"(majority-class baseline {m['majority_class_baseline']:.1%})",
        ),
        (
            "Same, with categorical values the model never saw",
            ", ".join(
                f"{name} {v['mean']:.1%} ± {v['sd']:.1%}" for name, v in unseen.items()
            )
            + f" (a model trained without countries: {no_country['mean']:.1%} "
            f"on the unseen-country alerts)",
        ),
        (
            "Pipeline triage vs rubric, 1,000-alert run",
            f"{r['pipeline_rubric_agreement_1000_alerts']:.1%}",
        ),
    ]
    repo = m.get("repo_triage_model_pkl_agreement_5x1000_unseen")
    if repo:
        rows.append(
            (
                "Local triage_model.pkl vs rubric (the file main.py loads)",
                f"{repo['mean']:.1%} ± {repo['sd']:.1%}",
            )
        )

    lines = [
        "## SOC pipeline benchmark (synthetic alerts)",
        "",
        "| Metric | Result |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in rows]
    lines += [
        "",
        "Notes:",
        "- Alerts, WHOIS and AbuseIPDB results are simulated; response actions write files only.",
        "- Enrichment sleeps 10 ms per alert to stand in for API calls, which bounds throughput.",
        "- The rubric is the rule-based scoring in AlertTriageClassifier.create_training_data;",
        "  agreement measures how faithfully the model reproduces it, not analyst accuracy.",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Benchmark the SOC pipeline")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    args = parser.parse_args()

    logging.disable(logging.CRITICAL)
    start_dir = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="soc-benchmark-") as workdir:
        os.chdir(workdir)
        try:
            results = run_benchmark()
        finally:
            os.chdir(start_dir)

    print(json.dumps(results, indent=2) if args.json else to_markdown(results))


if __name__ == "__main__":
    main()
