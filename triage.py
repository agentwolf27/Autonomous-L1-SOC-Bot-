import pandas as pd
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    # Fit on the data
                    self.label_encoders[col].fit(features_df[col].astype(str))

                try:
                    features_df[f"{col}_encoded"] = self.label_encoders[col].transform(
                        features_df[col].astype(str)
                    )
                except ValueError:
                    # Handle unseen labels by fitting on current data
                    unique_values = features_df[col].astype(str).unique()
                    all_values = list(self.label_encoders[col].classes_) + list(
                        unique_values
                    )
                    self.label_encoders[col].fit(all_values)
                    features_df[f"{col}_encoded"] = self.label_encoders[col].transform(
                        features_df[col].astype(str)
                    )

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

        # Fill NaN values with 0
        X = X.fillna(0)

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

    def train(self, df):
        """Train the classification model"""
        logger.info("Training triage classification model...")

        # Create training data with labels
        training_df = self.create_training_data(df)

        # Prepare features
        X = self.prepare_features(training_df)
        y = training_df["risk_level"]

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train model
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        logger.info(f"Model trained with accuracy: {accuracy:.3f}")
        logger.info("\nClassification Report:")
        logger.info(f"\n{classification_report(y_test, y_pred)}")

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
        empty_df["risk_level"] = pd.Series(dtype='object')
        empty_df["risk_score"] = pd.Series(dtype='float64')
        empty_df["triage_timestamp"] = pd.Series(dtype='datetime64[ns]')
        empty_df["confidence"] = pd.Series(dtype='float64')
        empty_df["priority"] = pd.Series(dtype='int64')
        return empty_df

    # Create triage classifier
    classifier = AlertTriageClassifier()

    # Try to load existing model, otherwise train new one
    if not classifier.load_model():
        logger.info("Training new triage model...")
        classifier.train(df)
        classifier.save_model()

    # Create result DataFrame
    triaged_df = df.copy()

    # Get predictions
    risk_levels, risk_scores = classifier.predict(df)

    # Add predictions to DataFrame
    triaged_df["risk_level"] = risk_levels
    triaged_df["risk_score"] = risk_scores.round(2)

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

    # Boost priority for certain critical conditions
    triaged_df.loc[
        (triaged_df["source_abuse_score"] > 90)
        | (triaged_df["event_type"] == "Malware Detection"),
        "priority",
    ] = 1

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
