#!/usr/bin/env python3
"""
Tests for the default triage model's training path
"""

import os
import random
import sys

import pandas as pd

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enrichment import enrich_alerts
from ingestion import generate_sample_alerts, normalize_alerts
from triage import build_reference_dataset, train_reference_model


def test_reference_model_matches_rubric_on_unseen_alerts(tmp_path, monkeypatch):
    """The default model reproduces the rule-based rubric on alerts it never saw"""
    model_path = tmp_path / "triage_model.pkl"
    model = train_reference_model(str(model_path))
    assert model_path.exists()

    # Enrich the way the pipeline does, minus the simulated API delay
    monkeypatch.setattr("enrichment.time.sleep", lambda seconds: None)
    random.seed(2024)
    unseen = enrich_alerts(pd.DataFrame(normalize_alerts(generate_sample_alerts(1000))))

    assert model.rubric_agreement(unseen) >= 0.9


def test_reference_dataset_is_reproducible_and_leaves_global_rng_alone():
    random.seed(7)
    expected_next = random.random()

    random.seed(7)
    first = build_reference_dataset(200, seed=1)
    assert random.random() == expected_next

    second = build_reference_dataset(200, seed=1)
    pd.testing.assert_frame_equal(
        first.drop(columns="timestamp"), second.drop(columns="timestamp")
    )
