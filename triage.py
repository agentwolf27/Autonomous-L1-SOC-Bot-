import pandas as pd
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import random
from datetime import datetime

from ingestion import generate_sample_alerts, normalize_alerts
from enrichment import enrich_single_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The default model is trained on this fixed synthetic set, never on a live batch
REFERENCE_TRAINING_ALERTS = 2000
REFERENCE_TRAINING_SEED = 42

# Categorical values the model never saw in training are scored as this reserved label;
# train() teaches the model what the rubric says about it (with_unseen_category_copies)
UNSEEN_CATEGORY = "__unseen__"
# Encoded value for unseen values when the model was trained without UNSEEN_CATEGORY
UNSEEN_CATEGORY_CODE = -1


class AlertTriageClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100, random_state=42, max_depth=10
        )
        self.label_encoders = {}
        self.feature_columns = [
            "source_abuse_score",
            "dest_abuse_score",
            "destination_port",
            "bytes_transferred",
            "external_source",
            "external_dest",
            "is_internal_traffic",
        ]
        self.categorical_columns = [
            "event_type",
            "severity",
            "protocol",
            "source_whois_country",
        ]
        self.is_trained = False

    def create_training_data(self, df):
        """Create labeled training data based on heuristic rules"""
        training_data = df.copy()

        # Initialize risk_level based on multiple factors
        risk_scores = np.zeros(len(training_data))

        # Factor 1: Abuse score
        risk_scores += training_data["source_abuse_score"] / 100 * 40  # 40% weight

        # Factor 2: High-risk countries
        high_risk_countries = ["RU", "CN", "IR", "KP", "Unknown"]
        risk_scores += (
            training_data["source_whois_country"].isin(high_risk_countries) * 20
        )

        # Factor 3: External traffic
        risk_scores += training_data["external_source"] * 15

        # Factor 4: High-risk ports
        high_risk_ports = [22, 23, 135, 139, 445, 993, 995]
        risk_scores += training_data["destination_port"].isin(high_risk_ports) * 10

        # Factor 5: Event type severity
        high_risk_events = [
            "Malware Detection",
            "Data Exfiltration",
            "Privilege Escalation",
            "DDoS Attack",
        ]
        medium_risk_events = [
            "Port Scan",
            "Brute Force Attack",
            "SQL Injection",
            "Cross-Site Scripting",
        ]

        risk_scores += training_data["event_type"].isin(high_risk_events) * 10
        risk_scores += training_data["event_type"].isin(medium_risk_events) * 5

        # Factor 6: Original severity
        severity_map = {"Critical": 20, "High": 15, "Medium": 10, "Low": 5}
        risk_scores += training_data["severity"].map(severity_map).fillna(5)

        # Factor 7: Large data transfers
        risk_scores += (training_data["bytes_transferred"] > 50000) * 5

        # Convert scores to categories
        training_data["risk_level"] = pd.cut(
            risk_scores,
            bins=[0, 30, 60, 1000],  # Changed upper bound to handle scores > 100
            labels=["Low", "Medium", "High"],
            include_lowest=True,
        )

        # Fill any NaN risk levels
        training_data["risk_level"] = training_data["risk_level"].fillna("Low")

        training_data["risk_score"] = np.clip(
            risk_scores, 0, 100
        )  # Clip scores to 0-100 range

        return training_data

    def prepare_features(self, df):
        """Prepare features for ML model"""
        features_df = df.copy()

        # Encode categorical variables
        for col in self.categorical_columns:
            if col in features_df.columns:
                values = features_df[col].astype(str)
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder().fit(values)

                # A label's code is its position in the sorted classes_, as transform()
                # gives. Unseen labels take UNSEEN_CATEGORY's code instead of a refit:
                # refitting re-sorts classes_ and shifts the codes of known categories.
                classes = pd.Index(self.label_encoders[col].classes_)
                codes = classes.get_indexer(values)
                unseen = codes == -1  # get_indexer's marker for a label not in classes_
                if unseen.any():
                    reserved = classes.get_indexer([UNSEEN_CATEGORY])[0]
                    outcome = f"scored as {UNSEEN_CATEGORY!r}"
                    if reserved == -1:
                        # The model predates unseen-category training; its forest
                        # scores this sentinel like the first class in sort order (D2)
                        reserved = UNSEEN_CATEGORY_CODE
                        outcome = f"encoded as {reserved}; run train_model.py"
                    preview = sorted({str(v) for v in values[unseen]})[:5]
                    logger.warning(
                        f"{col}: {unseen.sum()} of {len(values)} alerts have values "
                        f"not seen in training, {outcome}: {preview}"
                    )
                    codes[unseen] = reserved
                features_df[f"{col}_encoded"] = codes

        # Create feature matrix
        feature_cols = self.feature_columns + [
            f"{col}_encoded"
            for col in self.categorical_columns
            if col in features_df.columns
        ]

        # Ensure all required columns exist
        for col in feature_cols:
            if col not in features_df.columns:
                logger.warning(f"Missing feature column: {col}")
                features_df[col] = 0

        # Get the feature columns and handle missing/NaN values
        X = features_df[feature_cols].copy()

        # Convert boolean columns to int
        for col in X.columns:
            if X[col].dtype == "bool":
                X[col] = X[col].astype(int)

        # Fill NaN values with 0 (infer dtypes first; fillna's implicit downcast is deprecated)
        X = X.infer_objects().fillna(0)

        # Ensure all columns are numeric
        for col in X.columns:
            if not pd.api.types.is_numeric_dtype(X[col]):
                try:
                    X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)
                except:
                    X[col] = 0

        # Final check for any remaining NaN values
        if X.isnull().any().any():
            logger.warning("Found NaN values, filling with 0")
            X = X.fillna(0)

        # Ensure all values are finite
        X = X.replace([np.inf, -np.inf], 0)

        return X

    def with_unseen_category_copies(self, df, copies=2, seed=0):
        """
        Return df followed by `copies` copies of its rows, each copy with a random,
        non-empty subset of its categorical values replaced by UNSEEN_CATEGORY.

        Labelled by the rubric, the copies teach the model what the rubric says about
        values it has never seen, alone or together. One copy left the result sensitive
        to which values happened to be hidden; two steady it. Uses its own RNG, so the
        global random state is untouched.
        """
        columns = [col for col in self.categorical_columns if col in df.columns]
        if not columns:
            return df

        rng = np.random.RandomState(seed)
        parts = [df]
        for _ in range(copies):
            hidden = rng.rand(len(df), len(columns)) < 0.5
            # A copy with nothing hidden would just repeat its row: hide one value there
            rows = np.flatnonzero(~hidden.any(axis=1))
            hidden[rows, rng.randint(len(columns), size=len(rows))] = True

            part = df.copy()
            for i, col in enumerate(columns):
                part[col] = part[col].astype(str).where(~hidden[:, i], UNSEEN_CATEGORY)
            parts.append(part)
        return pd.concat(parts, ignore_index=True)

    def train(self, df):
        """Train the classification model"""
        logger.info("Training triage classification model...")

        # Create training data with labels, and hold out 20% of the real alerts
        training_df = self.create_training_data(df)
        train_df, test_df = train_test_split(
            training_df,
            test_size=0.2,
            random_state=42,
            stratify=training_df["risk_level"],
        )

        # Train on the rest plus rubric-labelled copies with some categories unseen
        train_df = self.create_training_data(self.with_unseen_category_copies(train_df))
        X_train = self.prepare_features(train_df)
        X_test = self.prepare_features(test_df)
        y_test = test_df["risk_level"]

        # Train model
        self.model.fit(X_train, train_df["risk_level"])

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        logger.info(f"Model trained with accuracy: {accuracy:.3f}")
        logger.info("\nClassification Report:")
        logger.info(f"\n{classification_report(y_test, y_pred)}")

        self.holdout_accuracy = accuracy
        self.is_trained = True

        return self

    def predict(self, df):
        """Predict risk levels for new alerts"""
        if not self.is_trained:
            logger.warning("Model not trained yet. Training on provided data...")
            self.train(df)

        # Prepare features
        X = self.prepare_features(df)

        # Predict risk levels
        risk_levels = self.model.predict(X)
        risk_probabilities = self.model.predict_proba(X)

        # Calculate risk scores (0-100)
        risk_scores = np.max(risk_probabilities, axis=1) * 100

        return risk_levels, risk_scores

    def rubric_agreement(self, df):
        """Fraction of alerts where the predicted risk level matches the rule-based rubric"""
        expected = self.create_training_data(df)["risk_level"].astype(str).to_numpy()
        predicted, _ = self.predict(df)
        return float((predicted == expected).mean())

    def save_model(self, filepath="triage_model.pkl"):
        """Save trained model to disk"""
        if not self.is_trained:
            logger.error("Cannot save untrained model")
            return

        model_data = {
            "model": self.model,
            "label_encoders": self.label_encoders,
            "feature_columns": self.feature_columns,
            "categorical_columns": self.categorical_columns,
        }

        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")

    def load_model(self, filepath="triage_model.pkl"):
        """Load trained model from disk"""
        if not os.path.exists(filepath):
            logger.warning(f"Model file {filepath} not found")
            return False

        try:
            model_data = joblib.load(filepath)
            self.model = model_data["model"]
            self.label_encoders = model_data["label_encoders"]
            self.feature_columns = model_data["feature_columns"]
            self.categorical_columns = model_data["categorical_columns"]
            self.is_trained = True
            logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


def build_reference_dataset(
    num_alerts=REFERENCE_TRAINING_ALERTS, seed=REFERENCE_TRAINING_SEED
):
    """
    Generate a reproducible set of enriched synthetic alerts.

    Alert generation and the simulated enrichment both draw from Python's global RNG, so it
    is seeded here and restored afterwards to leave the caller's randomness untouched.
    """
    state = random.getstate()
    random.seed(seed)
    try:
        alerts = pd.DataFrame(normalize_alerts(generate_sample_alerts(num_alerts)))
        # Call the per-alert enricher directly to skip enrich_alerts' simulated API delay
        enrichment = pd.DataFrame(
            [enrich_single_alert(row) for _, row in alerts.iterrows()]
        )
    finally:
        random.setstate(state)
    return pd.concat([alerts, enrichment], axis=1)


def train_reference_model(
    filepath="triage_model.pkl",
    num_alerts=REFERENCE_TRAINING_ALERTS,
    seed=REFERENCE_TRAINING_SEED,
):
    """Train the triage model on the reference dataset and save it to filepath"""
    classifier = AlertTriageClassifier().train(
        build_reference_dataset(num_alerts, seed)
    )
    classifier.save_model(filepath)
    return classifier


def triage(df):
    """
    Main triage function that classifies alerts and assigns risk scores

    Args:
        df: Pandas DataFrame with enriched alert data

    Returns:
        DataFrame with added risk_level and risk_score columns
    """
    logger.info(f"Starting triage for {len(df)} alerts")

    # Handle empty DataFrame
    if df.empty:
        logger.warning("Empty DataFrame provided for triage")
        empty_df = df.copy()
        # Add expected columns with appropriate types
        empty_df["risk_level"] = pd.Series(dtype="object")
        empty_df["risk_score"] = pd.Series(dtype="float64")
        empty_df["triage_timestamp"] = pd.Series(dtype="datetime64[ns]")
        empty_df["confidence"] = pd.Series(dtype="float64")
        empty_df["priority"] = pd.Series(dtype="int64")
        return empty_df

    # Create triage classifier
    classifier = AlertTriageClassifier()

    # Try to load existing model, otherwise train one on the reference dataset.
    # Training on the incoming batch left a 50-alert run with only 40 training rows.
    if not classifier.load_model():
        logger.info("No saved model found, training on the reference dataset...")
        classifier = train_reference_model()

    # Create result DataFrame
    triaged_df = df.copy()

    # Get predictions
    try:
        risk_levels, risk_scores = classifier.predict(df)
    except Exception as e:
        # Handle malformed data or feature mismatch gracefully
        logger.warning(f"ML prediction failed, using default risk assessment: {e}")
        # Assign default risk levels based on simple heuristics
        risk_levels = ["Medium"] * len(df)  # Default to Medium risk
        risk_scores = [50.0] * len(df)  # Default 50% risk score

    # Add predictions to DataFrame
    triaged_df["risk_level"] = risk_levels
    # Handle both numpy arrays and lists
    if hasattr(risk_scores, "round"):
        triaged_df["risk_score"] = risk_scores.round(2)
    else:
        triaged_df["risk_score"] = [round(score, 2) for score in risk_scores]

    # Add triage timestamp
    triaged_df["triage_timestamp"] = datetime.now()

    # Calculate confidence intervals (0-1 scale for tests)
    triaged_df["confidence"] = np.where(
        triaged_df["risk_score"] > 80,
        0.9,
        np.where(triaged_df["risk_score"] > 50, 0.7, 0.5),
    )

    # Add priority based on risk level and other factors
    priority_map = {"High": 1, "Medium": 2, "Low": 3}
    triaged_df["priority"] = triaged_df["risk_level"].map(priority_map)

    # Boost priority for certain critical conditions (with safe column access)
    try:
        condition = False
        if "source_abuse_score" in triaged_df.columns:
            condition |= triaged_df["source_abuse_score"] > 90
        if "event_type" in triaged_df.columns:
            condition |= triaged_df["event_type"] == "Malware Detection"

        if condition is not False:  # Only apply if we have valid conditions
            triaged_df.loc[condition, "priority"] = 1
    except Exception as e:
        logger.warning(f"Failed to boost priority for critical conditions: {e}")

    # Sort by priority and risk score
    triaged_df = triaged_df.sort_values(
        ["priority", "risk_score"], ascending=[True, False]
    )
    triaged_df = triaged_df.reset_index(drop=True)

    # Log summary statistics
    risk_summary = triaged_df["risk_level"].value_counts()
    logger.info(f"Triage completed. Risk distribution: {risk_summary.to_dict()}")

    return triaged_df


def get_triage_summary(df):
    """Generate summary statistics for triaged alerts"""
    summary = {
        "total_alerts": len(df),
        "high_risk_count": len(df[df["risk_level"] == "High"]),
        "medium_risk_count": len(df[df["risk_level"] == "Medium"]),
        "low_risk_count": len(df[df["risk_level"] == "Low"]),
        "avg_risk_score": df["risk_score"].mean(),
        "high_risk_percentage": (len(df[df["risk_level"] == "High"]) / len(df) * 100),
        "critical_alerts": len(
            df[(df["risk_level"] == "High") & (df["priority"] == 1)]
        ),
    }
    return summary


if __name__ == "__main__":
    # Test triage with sample data
    from ingestion import ingest_alerts
    from enrichment import enrich_alerts

    # Get and enrich sample alerts
    alerts_df = ingest_alerts()
    enriched_df = enrich_alerts(alerts_df)

    # Perform triage
    triaged_df = triage(enriched_df)

    print(f"Triaged {len(triaged_df)} alerts")
    print("\nRisk Level Distribution:")
    print(triaged_df["risk_level"].value_counts())

    print("\nTop 5 High-Risk Alerts:")
    high_risk = triaged_df[triaged_df["risk_level"] == "High"].head()
    print(
        high_risk[
            ["id", "event_type", "source_ip", "risk_score", "risk_factors"]
        ].to_string()
    )

    # Get summary
    summary = get_triage_summary(triaged_df)
    print(f"\nTriage Summary: {summary}")
