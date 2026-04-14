"""
Stage 3 — Intent Classifier Trainer
======================================
Trains a TF-IDF + Logistic Regression classifier on MPDD data.
  - Vectorizer fitted ONLY on training split (no leakage)
  - Test set evaluated but never seen during fitting
  - Saves artifacts to data/models/stage3/

Artifacts saved:
  data/models/stage3/model.pkl          — LogisticRegression
  data/models/stage3/vectorizer.pkl     — TfidfVectorizer (fitted)
  data/models/stage3/label_encoder.pkl  — LabelEncoder
  data/models/stage3/metadata.json      — metrics + config

Labels:   VALID  (benign)  |  INVALID  (malicious)
Risk map: VALID -> LOW      |  INVALID -> HIGH
"""

import json
import pickle
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT  = Path(__file__).resolve().parents[2]
TRAIN_FILE    = PROJECT_ROOT / "data" / "processed" / "stage3_train.csv"
TEST_FILE     = PROJECT_ROOT / "data" / "processed" / "stage3_test.csv"
OUTPUT_DIR    = PROJECT_ROOT / "data" / "models" / "stage3"

RISK_MAP = {"VALID": "LOW", "INVALID": "HIGH"}

# -- TF-IDF config ------------------------------------------------------------
TFIDF_CONFIG = {
    "max_features":  8000,
    "ngram_range":   (1, 2),
    "sublinear_tf":  True,      # log(1+tf) — better for long texts
    "min_df":        2,         # ignore extremely rare terms
    "max_df":        0.95,      # ignore terms in >95% of docs
    "strip_accents": "unicode",
    "analyzer":      "word",
}

# -- Classifier config --------------------------------------------------------
LR_CONFIG = {
    "C":           1.0,
    "max_iter":    1000,
    "solver":      "lbfgs",
    "multi_class": "auto",
    "random_state": 42,
    "class_weight": "balanced",  # handles any class imbalance
}


def load_splits() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load pre-split train and test sets."""
    for path in (TRAIN_FILE, TEST_FILE):
        if not path.exists():
            print(f"[ERROR] File not found: {path}")
            print("        Run ml/preprocess/stage3_mpdd_prep.py first.")
            sys.exit(1)

    train = pd.read_csv(TRAIN_FILE, encoding="utf-8")
    test  = pd.read_csv(TEST_FILE,  encoding="utf-8")
    return train, test


def print_section(title: str) -> None:
    print(f"\n{'-'*60}")
    print(f"  {title}")
    print(f"{'-'*60}")


def main() -> None:
    print("=" * 60)
    print("Stage 3 — Intent Classifier Trainer")
    print("=" * 60)

    train_df, test_df = load_splits()
    print(f"[INFO] Train: {len(train_df)} rows | Test: {len(test_df)} rows")

    X_train = train_df["text"].astype(str).tolist()
    y_train = train_df["label"].tolist()
    X_test  = test_df["text"].astype(str).tolist()
    y_test  = test_df["label"].tolist()

    # -- Step 1: Fit TF-IDF on TRAIN only ------------------------------------
    print_section("Step 1: Fitting TF-IDF Vectorizer (train set only)")
    t0 = time.time()
    vectorizer = TfidfVectorizer(**TFIDF_CONFIG)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)       # transform only — no fit
    print(f"[INFO] Vocabulary size  : {len(vectorizer.vocabulary_):,}")
    print(f"[INFO] Train matrix     : {X_train_vec.shape}")
    print(f"[INFO] Test  matrix     : {X_test_vec.shape}")
    print(f"[INFO] Done in {time.time()-t0:.1f}s")

    # -- Step 2: Encode labels ------------------------------------------------
    print_section("Step 2: Label Encoding")
    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_test_enc  = le.transform(y_test)
    print(f"[INFO] Classes: {le.classes_.tolist()}")

    # -- Step 3: Train Logistic Regression -----------------------------------
    print_section("Step 3: Training Logistic Regression")
    t0 = time.time()
    clf = LogisticRegression(**LR_CONFIG)
    clf.fit(X_train_vec, y_train_enc)
    print(f"[INFO] Training done in {time.time()-t0:.1f}s")
    print(f"       Iterations used: {clf.n_iter_[0]}")

    # -- Step 4: Evaluate on held-out test set -------------------------------
    print_section("Step 4: Evaluation on Held-Out Test Set")
    y_pred     = clf.predict(X_test_vec)
    y_proba    = clf.predict_proba(X_test_vec)
    accuracy   = accuracy_score(y_test_enc, y_pred)
    conf_mat   = confusion_matrix(y_test_enc, y_pred)

    # AUC (binary-safe)
    try:
        auc = roc_auc_score(y_test_enc, y_proba[:, 1])
    except Exception:
        auc = float("nan")

    print(f"\n  Accuracy : {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"  ROC-AUC  : {auc:.4f}")
    print(f"\n  Confusion Matrix:")
    class_names = le.classes_.tolist()
    header = "         " + "  ".join(f"{c:>8}" for c in class_names)
    print(header)
    for i, row in enumerate(conf_mat):
        row_str = "  ".join(f"{v:>8}" for v in row)
        print(f"  {class_names[i]:>6}  {row_str}")

    print(f"\n  Classification Report:")
    report = classification_report(y_test_enc, y_pred, target_names=class_names, digits=4)
    print(report)

    # -- Step 5: Save artifacts -----------------------------------------------
    print_section("Step 5: Saving Artifacts")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    model_path   = OUTPUT_DIR / "model.pkl"
    vec_path     = OUTPUT_DIR / "vectorizer.pkl"
    le_path      = OUTPUT_DIR / "label_encoder.pkl"
    meta_path    = OUTPUT_DIR / "metadata.json"

    with open(model_path,  "wb") as fh: pickle.dump(clf,        fh)
    with open(vec_path,    "wb") as fh: pickle.dump(vectorizer, fh)
    with open(le_path,     "wb") as fh: pickle.dump(le,         fh)

    metadata = {
        "model_type":       "LogisticRegression",
        "tfidf_config":     {**TFIDF_CONFIG, "ngram_range": list(TFIDF_CONFIG["ngram_range"])},
        "lr_config":        LR_CONFIG,
        "train_size":       len(X_train),
        "test_size":        len(X_test),
        "vocabulary_size":  len(vectorizer.vocabulary_),
        "classes":          class_names,
        "risk_map":         RISK_MAP,
        "accuracy":         round(accuracy, 6),
        "roc_auc":          round(auc, 6) if not np.isnan(auc) else None,
        "confusion_matrix": conf_mat.tolist(),
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "is_trained":       True,
    }
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"[OK]   model.pkl       -> {model_path}")
    print(f"[OK]   vectorizer.pkl  -> {vec_path}")
    print(f"[OK]   label_encoder   -> {le_path}")
    print(f"[OK]   metadata.json   -> {meta_path}")

    if accuracy >= 0.85:
        print(f"\n[OK]  Accuracy {accuracy*100:.2f}% meets the >=85% target.")
    else:
        print(f"\n[WARN]  Accuracy {accuracy*100:.2f}% is below 85% target.")
        print("   Consider increasing max_features or using more data.")


if __name__ == "__main__":
    main()
