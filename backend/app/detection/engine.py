"""Known-threat detection engine (Random Forest) for DIODEx.

Trains a multi-class Random Forest on the seven synthetic flow datasets
(normal + the six known threats), persists the model and feature/class
metadata under backend/artifacts/, and exposes a reusable per-flow
predictor.

Train from backend/ with:
    python -m app.detection.engine

This module intentionally does NOT implement Isolation Forest, alert
correlation, risk scoring, evidence, incidents, or LLM explanations.
"""

from __future__ import annotations

import argparse
import json
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from app.features.extractor import FEATURE_COLUMNS, extract_features
from app.ingestion.csv_loader import load_flows_from_csv

# backend/app/detection/engine.py -> backend/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
ARTIFACT_DIR = PROJECT_ROOT / "artifacts"

MODEL_FILENAME = "rf_known_threat.joblib"
META_FILENAME = "rf_known_threat_meta.json"

RANDOM_STATE = 42
TEST_SIZE = 0.25
N_ESTIMATORS = 300

NORMAL_LABEL = "normal"
THREAT_CLASSES = ["ddos", "c2", "dga", "tls", "scan", "exfil"]
DATASET_FILES = [f"{label}.csv" for label in [NORMAL_LABEL, *THREAT_CLASSES]]


def _build_dataset(data_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load every dataset CSV and build (feature matrix, class labels).

    Raw source/destination IPs are never used: features come exclusively
    from extract_features(), which already excludes them.
    """
    X_rows: list[list[float]] = []
    y_labels: list[str] = []
    for filename in DATASET_FILES:
        path = data_dir / filename
        if not path.is_file():
            raise FileNotFoundError(
                f"Dataset not found: {path}. "
                f"Run backend/data/generate_datasets.py first."
            )
        label = path.stem
        for record in load_flows_from_csv(path):
            features = extract_features(record)
            # Fixed, documented column order -- never dict iteration order.
            X_rows.append([float(features[c]) for c in FEATURE_COLUMNS])
            y_labels.append(label)
    return np.asarray(X_rows, dtype=np.float64), np.asarray(y_labels)


def train_known_threat_model(
    data_dir: Path | str = DATA_DIR,
    artifact_dir: Path | str = ARTIFACT_DIR,
) -> dict:
    """Train the 7-class Random Forest and persist model + metadata.

    Returns a small summary dict (paths, accuracy, classes).
    """
    data_dir = Path(data_dir)
    artifact_dir = Path(artifact_dir)

    X, y = _build_dataset(data_dir)

    # Stratified split: every class keeps ~75/25 train/test proportion.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nAccuracy on held-out test set: {accuracy:.4f}\n")
    print(classification_report(y_test, y_pred))

    artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifact_dir / MODEL_FILENAME
    meta_path = artifact_dir / META_FILENAME

    joblib.dump(model, model_path)

    # Feature order + classes are stored so prediction stays aligned even if
    # the extractor or training data changes later.
    meta = {
        "feature_columns": list(FEATURE_COLUMNS),
        "classes": model.classes_.tolist(),
        "n_estimators": N_ESTIMATORS,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "n_samples": int(len(X)),
        "n_features": int(X.shape[1]),
        "accuracy": float(accuracy),
    }
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"Saved model -> {model_path}")
    print(f"Saved meta  -> {meta_path}")
    return {
        "model_path": str(model_path),
        "meta_path": str(meta_path),
        "accuracy": float(accuracy),
        "classes": meta["classes"],
        "n_samples": meta["n_samples"],
    }


@lru_cache(maxsize=1)
def _load_model() -> tuple[object, dict]:
    """Load the trained model + metadata once, then cache it."""
    model_path = ARTIFACT_DIR / MODEL_FILENAME
    meta_path = ARTIFACT_DIR / META_FILENAME
    if not model_path.is_file() or not meta_path.is_file():
        raise FileNotFoundError(
            f"No trained model at {model_path}. "
            f"Run train_known_threat_model() or `python -m app.detection.engine` first."
        )
    model = joblib.load(model_path)
    meta = json.loads(meta_path.read_text())
    return model, meta


def predict_known_threat(flow) -> dict:
    """Classify a single Flow-compatible record (ORM instance or dict).

    Returns:
        {
          "threat_name": str,      # one of the 7 classes; may be "normal"
          "confidence": float,     # probability of the predicted class
          "is_threat": bool,       # True when threat_name != "normal"
          "probabilities": {...},  # full per-class probability map
        }
    """
    model, meta = _load_model()

    features = extract_features(flow)
    # Reorder by the columns the model was trained on (stored in metadata).
    row = np.asarray(
        [[float(features[c]) for c in meta["feature_columns"]]],
        dtype=np.float64,
    )

    proba = model.predict_proba(row)[0]
    idx = int(np.argmax(proba))
    threat_name = str(model.classes_[idx])

    return {
        "threat_name": threat_name,
        "confidence": float(proba[idx]),
        "is_threat": threat_name != NORMAL_LABEL,
        "probabilities": {
            str(c): float(p) for c, p in zip(model.classes_, proba)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the DIODEx known-threat Random Forest."
    )
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR,
                        help="directory containing the 7 class CSVs")
    parser.add_argument("--artifact-dir", type=Path, default=ARTIFACT_DIR,
                        help="where to write the .joblib model and meta JSON")
    args = parser.parse_args()

    train_known_threat_model(data_dir=args.data_dir,
                             artifact_dir=args.artifact_dir)


if __name__ == "__main__":
    main()
