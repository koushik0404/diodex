"""Isolation Forest unknown-behavior detector for DIODEx.

Trains exclusively on NORMAL traffic (backend/data/normal.csv) so that any
unseen/unknown behavior stands out as anomalous. The six known-threat
labels are deliberately NOT used to train this model.

Train from backend/ with:
    python -m app.anomaly.isolation_forest

Model + metadata are persisted under backend/artifacts/.
"""

from __future__ import annotations

import argparse
import json
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.features.extractor import FEATURE_COLUMNS, extract_features
from app.ingestion.csv_loader import load_flows_from_csv

# backend/app/anomaly/isolation_forest.py -> backend/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
ARTIFACT_DIR = PROJECT_ROOT / "artifacts"

MODEL_FILENAME = "isolation_forest.joblib"
META_FILENAME = "isolation_forest_meta.json"

RANDOM_STATE = 42
N_ESTIMATORS = 200
# The training set is pure normal traffic, so "contamination" is not a real
# outlier fraction -- it acts as the sensitivity knob (how much of the normal
# training distribution may sit on the anomaly side). Lower = stricter.
DEFAULT_CONTAMINATION = 0.05

NORMAL_DATASET = "normal.csv"


def _load_normal_features(data_dir: Path) -> np.ndarray:
    """Load normal.csv and build a feature matrix (raw IPs never used)."""
    path = data_dir / NORMAL_DATASET
    if not path.is_file():
        raise FileNotFoundError(
            f"Normal dataset not found: {path}. "
            f"Run backend/data/generate_datasets.py first."
        )
    rows: list[list[float]] = []
    for record in load_flows_from_csv(path):
        features = extract_features(record)
        rows.append([float(features[c]) for c in FEATURE_COLUMNS])
    if not rows:
        raise ValueError(f"No flow records loaded from {path}")
    return np.asarray(rows, dtype=np.float64)


def train_anomaly_model(
    data_dir: Path | str = DATA_DIR,
    artifact_dir: Path | str = ARTIFACT_DIR,
    contamination: float = DEFAULT_CONTAMINATION,
    n_estimators: int = N_ESTIMATORS,
    random_state: int = RANDOM_STATE,
) -> dict:
    """Train IsolationForest on normal traffic only and persist it."""
    data_dir = Path(data_dir)
    artifact_dir = Path(artifact_dir)

    X = _load_normal_features(data_dir)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)

    artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifact_dir / MODEL_FILENAME
    meta_path = artifact_dir / META_FILENAME

    joblib.dump(model, model_path)

    meta = {
        "feature_columns": list(FEATURE_COLUMNS),
        "n_estimators": n_estimators,
        "contamination": contamination,
        "random_state": random_state,
        "n_samples": int(len(X)),
        "n_features": int(X.shape[1]),
        "note": (
            "anomaly_score = clip(0.5 - decision_function, 0, 1); "
            "is_anomaly == True iff anomaly_score > 0.5"
        ),
    }
    meta_path.write_text(json.dumps(meta, indent=2))

    flagged = int(np.sum(model.predict(X) == -1))
    print(f"Trained IsolationForest on {len(X)} normal flows "
          f"({flagged} flagged anomalous in training, ~{flagged / len(X):.1%}).")
    print(f"Saved model -> {model_path}")
    print(f"Saved meta  -> {meta_path}")

    return {
        "model_path": str(model_path),
        "meta_path": str(meta_path),
        "n_samples": meta["n_samples"],
        "train_flag_rate": flagged / len(X),
    }


@lru_cache(maxsize=1)
def _load_model() -> tuple[IsolationForest, dict]:
    """Load the trained model + metadata once, then cache it."""
    model_path = ARTIFACT_DIR / MODEL_FILENAME
    meta_path = ARTIFACT_DIR / META_FILENAME
    if not model_path.is_file() or not meta_path.is_file():
        raise FileNotFoundError(
            f"No trained anomaly model at {model_path}. "
            f"Run train_anomaly_model() or "
            f"`python -m app.anomaly.isolation_forest` first."
        )
    model = joblib.load(model_path)
    meta = json.loads(meta_path.read_text())
    return model, meta


def predict_anomaly(flow) -> dict:
    """Score one Flow-compatible record (ORM instance or dict).

    Returns:
        {
          "is_anomaly": bool,    # True when the flow is an outlier
          "anomaly_score": float # 0.0 (very normal) .. 1.0 (very anomalous)
        }

    Score convention: sklearn's decision_function is lower for more anomalous
    samples and is < 0 exactly when predict() flags the sample. Mapping
    score = clip(0.5 - decision, 0, 1) therefore yields is_anomaly == True
    iff anomaly_score > 0.5, with a clean 0..1 scale for downstream use.
    """
    model, meta = _load_model()

    features = extract_features(flow)
    # Reorder by the columns the model was trained on (stored in metadata).
    row = np.asarray(
        [[float(features[c]) for c in meta["feature_columns"]]],
        dtype=np.float64,
    )

    decision = float(model.decision_function(row)[0])  # lower = more anomalous
    is_anomaly = bool(model.predict(row)[0] == -1)
    anomaly_score = float(np.clip(0.5 - decision, 0.0, 1.0))

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the DIODEx Isolation Forest on normal traffic."
    )
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR,
                        help="directory containing normal.csv")
    parser.add_argument("--artifact-dir", type=Path, default=ARTIFACT_DIR,
                        help="where to write the .joblib model and meta JSON")
    parser.add_argument("--contamination", type=float,
                        default=DEFAULT_CONTAMINATION,
                        help="sensitivity knob (default: 0.05)")
    parser.add_argument("--n-estimators", type=int, default=N_ESTIMATORS,
                        help="number of trees (default: 200)")
    args = parser.parse_args()

    train_anomaly_model(
        data_dir=args.data_dir,
        artifact_dir=args.artifact_dir,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
    )


if __name__ == "__main__":
    main()
