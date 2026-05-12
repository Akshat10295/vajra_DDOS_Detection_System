"""
train.py — Vajra ML Pipeline: Train → Evaluate → Version → Deploy
==================================================================
Called by vajra_server.py's /api/retrain endpoint, OR run manually.

Pipeline stages:
  1. LOAD    — reads training_data_live.csv (collected by the detector)
  2. CLEAN   — drops duplicates, handles class imbalance with SMOTE
  3. TRAIN   — RandomForest with GridSearchCV for best hyperparameters
  4. EVALUATE— accuracy, precision, recall, F1, confusion matrix
  5. VERSION — saves timestamped copy in models/ folder
  6. DEPLOY  — writes ddos_model_new.pkl + scaler_new.pkl
               (vajra_server.py hot-swaps these automatically)

Output files (picked up by server hot-swap):
    ddos_model_new.pkl
    scaler_new.pkl
    feature_list.pkl       (only updated if feature set changed)
    training_report.json   (accuracy metrics, read by dashboard)

Usage:
    python train.py                         # uses training_data_live.csv
    python train.py --data my_dataset.csv   # custom CSV
    python train.py --no-smote              # skip oversampling
    python train.py --quick                 # skip GridSearch, use defaults
"""

import argparse
import json
import os
import shutil
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, f1_score, precision_score, recall_score
)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

TRAINING_CSV   = "training_data_live.csv"
MODELS_DIR     = Path("models")           # versioned model archive
REPORT_FILE    = "training_report.json"   # read by dashboard

# Features used for training (must match extract_features() in detector)
FEATURE_COLS = [
    "frame.len",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.flags.push",
    "tcp.flags.syn",
]

LABEL_COL = "label"

# Minimum samples needed before training makes sense
MIN_SAMPLES       = 50
MIN_ATTACK_SAMPLES = 10

# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def ensure_models_dir():
    MODELS_DIR.mkdir(exist_ok=True)


def version_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ──────────────────────────────────────────────
#  STAGE 1 — LOAD DATA
# ──────────────────────────────────────────────

def load_data(csv_path: str) -> pd.DataFrame:
    log(f"Loading data from: {csv_path}")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Training CSV not found: {csv_path}\n"
            "Start the detector first to collect live traffic data."
        )

    df = pd.read_csv(csv_path)
    log(f"Loaded {len(df)} rows, {df.columns.tolist()}")

    # Validate required columns
    missing = [c for c in FEATURE_COLS + [LABEL_COL] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in CSV: {missing}")

    return df

# ──────────────────────────────────────────────
#  STAGE 2 — CLEAN & BALANCE
# ──────────────────────────────────────────────

def clean_data(df: pd.DataFrame, use_smote: bool = True) -> tuple[np.ndarray, np.ndarray]:
    log("Cleaning data...")

    # Drop rows with NaN in feature or label cols
    df = df.dropna(subset=FEATURE_COLS + [LABEL_COL])

    # Drop full duplicates
    before = len(df)
    df = df.drop_duplicates()
    log(f"Dropped {before - len(df)} duplicate rows")

    # Encode label as int
    df[LABEL_COL] = df[LABEL_COL].astype(int)

    # Check class distribution
    class_counts = df[LABEL_COL].value_counts().to_dict()
    log(f"Class distribution: {class_counts}")

    normal_count = class_counts.get(0, 0)
    attack_count = class_counts.get(1, 0)

    if normal_count < 10:
        raise ValueError(f"Too few normal samples ({normal_count}). Collect more traffic data.")
    if attack_count < MIN_ATTACK_SAMPLES:
        raise ValueError(
            f"Too few attack samples ({attack_count} < {MIN_ATTACK_SAMPLES}). "
            "Run the attacker simulation longer to collect more attack packets."
        )

    X = df[FEATURE_COLS].values
    y = df[LABEL_COL].values

    # SMOTE oversampling if class imbalance is significant
    if use_smote and abs(normal_count - attack_count) > 0.2 * len(df):
        try:
            from imblearn.over_sampling import SMOTE
            log("Applying SMOTE to balance classes...")
            sm   = SMOTE(random_state=42, k_neighbors=min(5, attack_count - 1))
            X, y = sm.fit_resample(X, y)
            unique, counts = np.unique(y, return_counts=True)
            log(f"After SMOTE: {dict(zip(unique.tolist(), counts.tolist()))}")
        except ImportError:
            log("imbalanced-learn not installed — skipping SMOTE (pip install imbalanced-learn)")
        except Exception as e:
            log(f"SMOTE failed ({e}) — proceeding without it")

    log(f"Final dataset: {len(X)} samples, {X.shape[1]} features")
    return X, y

# ──────────────────────────────────────────────
#  STAGE 3 — TRAIN
# ──────────────────────────────────────────────

def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    quick: bool = False
) -> RandomForestClassifier:

    if quick:
        log("Quick mode — training with default hyperparameters...")
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        )
        clf.fit(X_train, y_train)
        return clf

    log("Running GridSearchCV to find best hyperparameters...")
    param_grid = {
        "n_estimators": [50, 100, 200],
        "max_depth":    [5, 10, None],
        "min_samples_split": [2, 5],
    }
    base_clf = RandomForestClassifier(
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    grid = GridSearchCV(
        base_clf,
        param_grid,
        cv=3,
        scoring="f1",
        n_jobs=-1,
        verbose=0
    )
    grid.fit(X_train, y_train)
    log(f"Best params: {grid.best_params_}  |  CV F1: {grid.best_score_:.4f}")
    return grid.best_estimator_

# ──────────────────────────────────────────────
#  STAGE 4 — EVALUATE
# ──────────────────────────────────────────────

def evaluate_model(
    clf: RandomForestClassifier,
    scaler: StandardScaler,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> dict:

    log("Evaluating model on held-out test set...")
    X_test_scaled = scaler.transform(X_test)
    y_pred        = clf.predict(X_test_scaled)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred).tolist()
    cr   = classification_report(y_test, y_pred, target_names=["Normal", "Attack"])

    report = {
        "timestamp":    datetime.now().isoformat(),
        "accuracy":     round(acc,  4),
        "precision":    round(prec, 4),
        "recall":       round(rec,  4),
        "f1_score":     round(f1,   4),
        "confusion_matrix": cm,
        "test_samples": len(y_test),
        "train_samples": 0,   # filled in later
        "features":     FEATURE_COLS,
        "model_type":   type(clf).__name__,
    }

    log(f"\n{'='*50}")
    log(f"  Accuracy : {acc:.4f}")
    log(f"  Precision: {prec:.4f}")
    log(f"  Recall   : {rec:.4f}")
    log(f"  F1 Score : {f1:.4f}")
    log(f"  Confusion Matrix:\n    {cm}")
    log(f"\n{cr}")
    log(f"{'='*50}\n")

    return report


def feature_importances(clf: RandomForestClassifier) -> dict:
    importances = clf.feature_importances_
    return {feat: round(float(imp), 4) for feat, imp in zip(FEATURE_COLS, importances)}

# ──────────────────────────────────────────────
#  STAGE 5 — VERSION (archive old models)
# ──────────────────────────────────────────────

def version_existing_model():
    """Move current production model into models/ with a timestamp."""
    ensure_models_dir()
    tag = version_tag()
    for src, dst in [
        ("ddos_model.pkl", MODELS_DIR / f"ddos_model_{tag}.pkl"),
        ("scaler.pkl",     MODELS_DIR / f"scaler_{tag}.pkl"),
    ]:
        if os.path.exists(src):
            shutil.copy2(src, dst)
            log(f"Versioned {src} → {dst}")

    # Keep only last 5 versions to save disk space
    archived = sorted(MODELS_DIR.glob("ddos_model_*.pkl"))
    if len(archived) > 5:
        for old in archived[:-5]:
            old.unlink()
            stem = old.stem.replace("ddos_model_", "scaler_")
            scaler_old = MODELS_DIR / f"{stem}.pkl"
            if scaler_old.exists():
                scaler_old.unlink()
            log(f"Pruned old version: {old.name}")

# ──────────────────────────────────────────────
#  STAGE 6 — DEPLOY (write _new files for hot-swap)
# ──────────────────────────────────────────────

def deploy_model(
    clf: RandomForestClassifier,
    scaler: StandardScaler,
    report: dict
):
    log("Deploying new model (writing _new files for hot-swap)...")

    # Write to _new files — server picks these up without restart
    joblib.dump(clf,          "ddos_model_new.pkl")
    joblib.dump(scaler,       "scaler_new.pkl")
    joblib.dump(FEATURE_COLS, "feature_list.pkl")   # always refresh

    # Save human-readable training report
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    log(f"Saved: ddos_model_new.pkl, scaler_new.pkl, feature_list.pkl")
    log(f"Saved: {REPORT_FILE}")
    log("Server will auto-detect and hot-swap the new model on next window tick.")

# ──────────────────────────────────────────────
#  FULL PIPELINE
# ──────────────────────────────────────────────

def run_pipeline(csv_path: str, use_smote: bool = True, quick: bool = False) -> dict:
    log("=" * 60)
    log("  VAJRA ML PIPELINE — STARTING")
    log("=" * 60)

    # 1. Load
    df = load_data(csv_path)

    if len(df) < MIN_SAMPLES:
        raise ValueError(
            f"Only {len(df)} samples in CSV (need ≥ {MIN_SAMPLES}). "
            "Run the simulation longer to collect more data."
        )

    # 2. Clean + balance
    X, y = clean_data(df, use_smote=use_smote)

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    log(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # 4. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # 5. Train
    clf = train_model(X_train_scaled, y_train, quick=quick)

    # 6. Evaluate
    report = evaluate_model(clf, scaler, X_test, y_test)
    report["train_samples"]    = len(X_train)
    report["feature_importance"] = feature_importances(clf)
    report["csv_path"]         = csv_path

    # 7. Version existing model
    version_existing_model()

    # 8. Deploy
    deploy_model(clf, scaler, report)

    log("=" * 60)
    log(f"  PIPELINE COMPLETE  |  F1={report['f1_score']:.4f}  Acc={report['accuracy']:.4f}")
    log("=" * 60)

    return report

# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vajra ML Training Pipeline")
    parser.add_argument("--data",     default=TRAINING_CSV,  help="Path to training CSV")
    parser.add_argument("--no-smote", action="store_true",   help="Disable SMOTE oversampling")
    parser.add_argument("--quick",    action="store_true",   help="Skip GridSearch, use default params")
    args = parser.parse_args()

    try:
        report = run_pipeline(
            csv_path  = args.data,
            use_smote = not args.no_smote,
            quick     = args.quick
        )
        # Exit 0 = success (vajra_server checks this)
        exit(0)
    except Exception as e:
        print(f"\n[PIPELINE ERROR] {e}")
        exit(1)
