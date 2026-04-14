"""
Pipeline Evaluation — Wild Attack Dataset
==========================================
Loads dataset/attack_simulation/wild_attacks.csv (eval-only, never trained on).
Runs each prompt through Stage 2 (embedding anomaly) and Stage 3 (intent classifier).
Reports detection rates, false negatives, and score distributions.

Usage:
    python ml/evaluate/evaluate_pipeline.py
    python ml/evaluate/evaluate_pipeline.py --max-rows 1000
"""

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT   = Path(__file__).resolve().parents[2]
WILD_ATTACKS   = PROJECT_ROOT / "dataset" / "attack_simulation" / "wild_attacks.csv"
CENTROID_FILE  = PROJECT_ROOT / "data" / "models" / "stage2" / "benign_centroid.npy"
S3_MODEL_DIR   = PROJECT_ROOT / "data" / "models" / "stage3"
OUTPUT_DIR     = PROJECT_ROOT / "data" / "eval_results"

ANOMALY_THRESHOLD = 0.10    # cosine_sim < 0.10 -> anomaly (benign avg=0.36, std=0.11)
INVALID_THRESHOLD = 0.50    # prob(INVALID) >= 0.50 -> flagged (Stage 3)


def load_stage2() -> tuple | None:
    """Load sentence-transformer model and benign centroid."""
    if not CENTROID_FILE.exists():
        print("[WARN] Centroid not found — Stage 2 will be skipped.")
        print(f"       Expected: {CENTROID_FILE}")
        return None
    try:
        # First try to import torch separately to catch DLL errors early
        import torch
        from sentence_transformers import SentenceTransformer
        model    = SentenceTransformer("all-MiniLM-L6-v2")
        centroid = np.load(CENTROID_FILE)
        return model, centroid
    except ImportError:
        print("[WARN] sentence-transformers not installed. Stage 2 skipped.")
        return None
    except Exception as e:
        print(f"[WARN] torch/sentence-transformers initialization failed: {e}")
        print("       Stage 2 skipped due to torch/tensor compatibility issues.")
        return None


def load_stage3() -> tuple | None:
    """Load TF-IDF + LogReg artifacts."""
    needed = ["model.pkl", "vectorizer.pkl", "label_encoder.pkl"]
    for f in needed:
        if not (S3_MODEL_DIR / f).exists():
            print(f"[WARN] Stage 3 artifact missing: {f}. Stage 3 will be skipped.")
            return None
    try:
        with open(S3_MODEL_DIR / "model.pkl",        "rb") as fh: clf = pickle.load(fh)
        with open(S3_MODEL_DIR / "vectorizer.pkl",   "rb") as fh: vec = pickle.load(fh)
        with open(S3_MODEL_DIR / "label_encoder.pkl","rb") as fh: le  = pickle.load(fh)
        return clf, vec, le
    except Exception as e:
        print(f"[WARN] Could not load Stage 3: {e}")
        return None


def stage2_score(model, centroid: np.ndarray, texts: list[str]) -> np.ndarray:
    """Return cosine similarity to centroid for each text. Lower = more anomalous."""
    print(f"  Processing {len(texts):,} texts in batches...")
    embeddings = model.encode(texts, batch_size=32, show_progress_bar=True,
                              convert_to_numpy=True, normalize_embeddings=True)
    sims = embeddings @ centroid
    return sims


def stage3_classify(clf, vec, le, texts: list[str]) -> tuple[list[str], np.ndarray]:
    """Return (labels, probabilities_of_INVALID)."""
    X = vec.transform(texts)
    preds  = clf.predict(X)
    probas = clf.predict_proba(X)

    labels = le.inverse_transform(preds)

    # Find INVALID column index
    classes = le.classes_.tolist()
    if "INVALID" in classes:
        invalid_idx = classes.index("INVALID")
        invalid_probs = probas[:, invalid_idx]
    else:
        invalid_probs = np.zeros(len(texts))

    return labels.tolist(), invalid_probs


def compute_metrics(
    n_total: int,
    s2_flagged: int,
    s3_flagged: int,
    either_flagged: int,
    both_flagged: int,
) -> dict:
    def pct(v): return round(v / n_total * 100, 2) if n_total > 0 else 0.0

    return {
        "total_attacks":          n_total,
        "stage2_detected":        s2_flagged,
        "stage2_detection_rate":  pct(s2_flagged),
        "stage3_detected":        s3_flagged,
        "stage3_detection_rate":  pct(s3_flagged),
        "either_detected":        either_flagged,
        "either_detection_rate":  pct(either_flagged),
        "both_detected":          both_flagged,
        "both_detection_rate":    pct(both_flagged),
        "missed_by_both":         n_total - either_flagged,
        "false_negative_rate":    pct(n_total - either_flagged),
    }


def main(max_rows: int | None = None) -> None:
    print("=" * 60)
    print("Pipeline Evaluation — Wild Attack Dataset")
    print("=" * 60)

    if not WILD_ATTACKS.exists():
        print(f"[ERROR] wild_attacks.csv not found: {WILD_ATTACKS}")
        print("        Run ml/preprocess/attack_sim_merge.py first.")
        sys.exit(1)

    df = pd.read_csv(WILD_ATTACKS)
    if max_rows:
        df = df.head(max_rows)
        print(f"[INFO] Sampling {max_rows} rows for speed")

    texts = df["text"].astype(str).tolist()
    print(f"[INFO] Evaluating {len(texts):,} attack samples")

    s2_assets = load_stage2()
    s3_assets = load_stage3()

    s2_sims    = None
    s2_flagged = 0
    s3_flagged = 0

    # -- Stage 2: Embedding Anomaly --------------------------------------------
    if s2_assets:
        model, centroid = s2_assets
        print("\n[Stage 2] Computing embedding similarities ...")
        t0 = time.time()
        s2_sims = stage2_score(model, centroid, texts)
        elapsed = time.time() - t0
        s2_detected = s2_sims < ANOMALY_THRESHOLD
        s2_flagged  = int(s2_detected.sum())
        print(f"  Threshold  : cosine_sim < {ANOMALY_THRESHOLD}")
        print(f"  Avg sim    : {s2_sims.mean():.4f}  (benign ~0.8+)")
        print(f"  Detected   : {s2_flagged:,} / {len(texts):,} ({s2_flagged/len(texts)*100:.1f}%)")
        print(f"  Time       : {elapsed:.1f}s")
    else:
        s2_detected = np.zeros(len(texts), dtype=bool)

    # -- Stage 3: Intent Classifier --------------------------------------------
    s3_labels    = None
    s3_probs     = None
    s3_detected  = np.zeros(len(texts), dtype=bool)

    if s3_assets:
        clf, vec, le = s3_assets
        print("\n[Stage 3] Running intent classifier ...")
        t0 = time.time()
        s3_labels, s3_probs = stage3_classify(clf, vec, le, texts)
        elapsed = time.time() - t0
        s3_detected  = np.array(s3_labels) == "INVALID"
        s3_flagged   = int(s3_detected.sum())
        print(f"  Avg P(INVALID): {s3_probs.mean():.4f}")
        print(f"  Detected       : {s3_flagged:,} / {len(texts):,} ({s3_flagged/len(texts)*100:.1f}%)")
        print(f"  Time           : {elapsed:.1f}s")

    # -- Combined Metrics ------------------------------------------------------
    either_detected = s2_detected | s3_detected
    both_detected   = s2_detected & s3_detected

    metrics = compute_metrics(
        n_total=len(texts),
        s2_flagged=int(s2_detected.sum()),
        s3_flagged=int(s3_detected.sum()),
        either_flagged=int(either_detected.sum()),
        both_flagged=int(both_detected.sum()),
    )

    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(f"  Total attack samples    : {metrics['total_attacks']:>8,}")
    print(f"  Stage 2 detection rate  : {metrics['stage2_detection_rate']:>7.2f}%  ({metrics['stage2_detected']:,} / {metrics['total_attacks']:,})")
    print(f"  Stage 3 detection rate  : {metrics['stage3_detection_rate']:>7.2f}%  ({metrics['stage3_detected']:,} / {metrics['total_attacks']:,})")
    print(f"  Combined (either)       : {metrics['either_detection_rate']:>7.2f}%  ({metrics['either_detected']:,} / {metrics['total_attacks']:,})")
    print(f"  Combined (both)         : {metrics['both_detection_rate']:>7.2f}%  ({metrics['both_detected']:,} / {metrics['total_attacks']:,})")
    print(f"  ----------------------------------------------------")
    print(f"  Missed by both stages   : {metrics['false_negative_rate']:>7.2f}%  ({metrics['missed_by_both']:,} / {metrics['total_attacks']:,})")

    grade = "[OK]" if metrics["either_detection_rate"] >= 80 else "[WARN]"
    print(f"\n{grade} Overall detection: {metrics['either_detection_rate']:.2f}% (target >=80%)")

    # -- Save results ----------------------------------------------------------
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results_file = OUTPUT_DIR / "wild_attacks_eval.json"
    with open(results_file, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\n[OK] Results saved -> {results_file}")

    # -- Sample misses ---------------------------------------------------------
    missed_mask = ~either_detected
    if missed_mask.sum() > 0:
        missed_texts = [texts[i] for i in range(len(texts)) if missed_mask[i]]
        print(f"\n[INFO] Sample missed attacks ({min(5, len(missed_texts))} of {len(missed_texts)}):")
        for t in missed_texts[:5]:
            print(f"  * {t[:100]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate pipeline on wild attack dataset")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Limit rows for quick evaluation (default: all)")
    args = parser.parse_args()
    main(max_rows=args.max_rows)
