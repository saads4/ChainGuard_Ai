"""
Stage 2 — Embedding Baseline Trainer
======================================
Loads data/processed/stage2_benign_texts.json (produced by stage2_benign_prep.py).
Uses sentence-transformers (all-MiniLM-L6-v2) to encode all benign texts in batches.
Computes the mean centroid embedding vector.
Saves:
  data/models/stage2/benign_centroid.npy   — numpy array (384-dim)
  data/models/stage2/metadata.json         — provenance info

The centroid is used at runtime by the EmbeddingDetector's AnomalyScorer:
  anomaly_score = 1 - cosine_similarity(input_embedding, centroid)
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT   = Path(__file__).resolve().parents[2]
INPUT_FILE     = PROJECT_ROOT / "data" / "processed" / "stage2_benign_texts.json"
OUTPUT_DIR     = PROJECT_ROOT / "data" / "models" / "stage2"
CENTROID_FILE  = OUTPUT_DIR / "benign_centroid.npy"
METADATA_FILE  = OUTPUT_DIR / "metadata.json"

MODEL_NAME  = "all-MiniLM-L6-v2"
BATCH_SIZE  = 64


def load_texts() -> list[str]:
    """Load preprocessed benign texts."""
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        print("        Run ml/preprocess/stage2_benign_prep.py first.")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    texts = data.get("texts", [])
    if not texts:
        print("[ERROR] No texts found in input file.")
        sys.exit(1)

    return texts


def encode_texts(model, texts: list[str]) -> np.ndarray:
    """Encode texts in batches, return matrix (N, embedding_dim)."""
    print(f"[INFO] Encoding {len(texts)} texts with model '{MODEL_NAME}' ...")
    print(f"       Batch size: {BATCH_SIZE}")

    t0 = time.time()
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,   # L2-normalize for cosine sim
    )
    elapsed = time.time() - t0
    print(f"[INFO] Encoding done in {elapsed:.1f}s")
    print(f"       Embedding matrix shape: {embeddings.shape}")
    return embeddings


def compute_centroid(embeddings: np.ndarray) -> np.ndarray:
    """Compute mean vector and re-normalize it."""
    centroid = np.mean(embeddings, axis=0)
    norm = np.linalg.norm(centroid)
    if norm > 0:
        centroid = centroid / norm    # re-normalize the centroid
    return centroid


def main() -> None:
    print("=" * 60)
    print("Stage 2 — Embedding Baseline Trainer")
    print("=" * 60)

    # Import here so graceful error if not installed
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[ERROR] sentence-transformers not installed.")
        print("        Run: pip install sentence-transformers")
        sys.exit(1)

    texts = load_texts()
    print(f"[INFO] Loaded {len(texts)} benign texts")

    print(f"[INFO] Loading model: {MODEL_NAME}")
    model = SentenceTransformer(MODEL_NAME)

    embeddings = encode_texts(model, texts)

    print("[INFO] Computing centroid ...")
    centroid = compute_centroid(embeddings)
    print(f"       Centroid shape: {centroid.shape}")
    print(f"       Centroid norm : {np.linalg.norm(centroid):.6f}")

    # Compute average similarity of all benign texts to centroid (baseline health check)
    sims = embeddings @ centroid          # dot product (embeddings already L2-normed)
    print(f"[INFO] Avg cosine sim to centroid: {sims.mean():.4f}  (std: {sims.std():.4f})")
    print(f"       Min: {sims.min():.4f}  Max: {sims.max():.4f}")

    # Save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    np.save(CENTROID_FILE, centroid)

    metadata = {
        "model_name":        MODEL_NAME,
        "n_samples":         len(texts),
        "embedding_dim":     int(centroid.shape[0]),
        "centroid_norm":     float(np.linalg.norm(centroid)),
        "avg_sim_to_centroid": float(sims.mean()),
        "std_sim_to_centroid": float(sims.std()),
        "min_sim":           float(sims.min()),
        "max_sim":           float(sims.max()),
        "timestamp":         datetime.utcnow().isoformat() + "Z",
        "centroid_file":     str(CENTROID_FILE),
    }
    with open(METADATA_FILE, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"\n[OK]   Centroid saved  -> {CENTROID_FILE}")
    print(f"[OK]   Metadata saved  -> {METADATA_FILE}")
    print("\n  Suggested anomaly threshold:")
    suggest_threshold = float(sims.mean() - 2 * sims.std())
    print(f"    cosine_sim < {suggest_threshold:.4f}  ->  flag as anomaly")
    print(f"    (mean - 2sigma of benign distribution)")


if __name__ == "__main__":
    main()
