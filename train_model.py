#!/usr/bin/env python3
"""
Retrain the triage model on the reference dataset and save it.

triage() only trains when no model file exists, so run this to replace a stale
triage_model.pkl (for example one trained by an older version on a single batch).
"""

import argparse

from triage import (
    REFERENCE_TRAINING_ALERTS,
    REFERENCE_TRAINING_SEED,
    train_reference_model,
)


def main():
    parser = argparse.ArgumentParser(description="Retrain the SOC triage model")
    parser.add_argument("--alerts", type=int, default=REFERENCE_TRAINING_ALERTS)
    parser.add_argument("--seed", type=int, default=REFERENCE_TRAINING_SEED)
    parser.add_argument("--output", default="triage_model.pkl")
    args = parser.parse_args()

    classifier = train_reference_model(args.output, args.alerts, args.seed)
    print(
        f"Saved {args.output}: {args.alerts} synthetic alerts (seed {args.seed}), "
        f"{classifier.holdout_accuracy:.1%} agreement with the rule-based rubric "
        f"on the 20% held-out split"
    )


if __name__ == "__main__":
    main()
