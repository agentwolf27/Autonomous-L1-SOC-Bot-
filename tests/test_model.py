#!/usr/bin/env python3
"""
Tests for the default triage model's training path
"""

import os
import random
import sys

import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enrichment import enrich_alerts
from ingestion import generate_sample_alerts, normalize_alerts
from triage import (
    UNSEEN_CATEGORY_CODE,
    build_reference_dataset,
    train_reference_model,
)


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


def test_unseen_category_leaves_known_codes_and_predictions_unchanged(tmp_path):
    """An event type the model never saw must not remap the categories it was trained on"""
    model = train_reference_model(str(tmp_path / "triage_model.pkl"))
    trained_classes = {
        col: encoder.classes_.copy() for col, encoder in model.label_encoders.items()
    }

    known = build_reference_dataset(200, seed=3)
    known_features = model.prepare_features(known)
    known_levels, known_scores = model.predict(known)

    # Sorting before every trained class is what made a refit shift all the known codes
    unseen_event = "AAA Unknown Event"
    assert unseen_event < trained_classes["event_type"][0]
    unseen_row = known.iloc[[0]].assign(event_type=unseen_event)
    batch = pd.concat([unseen_row, known], ignore_index=True)

    batch_features = model.prepare_features(batch)
    batch_levels, batch_scores = model.predict(batch)

    assert batch_features["event_type_encoded"].iloc[0] == UNSEEN_CATEGORY_CODE
    pd.testing.assert_frame_equal(
        batch_features.iloc[1:].reset_index(drop=True), known_features
    )
    np.testing.assert_array_equal(
        known_features["event_type_encoded"],
        model.label_encoders["event_type"].transform(known["event_type"]),
    )
    np.testing.assert_array_equal(batch_levels[1:], known_levels)
    np.testing.assert_array_equal(batch_scores[1:], known_scores)
    for col, classes in trained_classes.items():
        np.testing.assert_array_equal(model.label_encoders[col].classes_, classes)
