"""
Stage 3 MPDD Data Preprocessor
================================
Loads dataset/stage3_training/MPDD.csv.
Maps isMalicious column: 0 -> VALID, 1 -> INVALID.
Performs stratified 80/20 train/test split (no data leakage).
Saves: data/processed/stage3_train.csv + stage3_test.csv

Column layout in MPDD.csv:
  Prompt       : str   — the input text
  isMalicious  : int   — 0 (benign) or 1 (malicious)
"""

import sys
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE   = PROJECT_ROOT / "dataset" / "stage3_training" / "MPDD.csv"
OUTPUT_DIR   = PROJECT_ROOT / "data" / "processed"
TRAIN_FILE   = OUTPUT_DIR / "stage3_train.csv"
TEST_FILE    = OUTPUT_DIR / "stage3_test.csv"

LABEL_MAP = {0: "VALID", 1: "INVALID"}
RANDOM_STATE = 42
TEST_SIZE    = 0.20


def detect_columns(df: pd.DataFrame) -> tuple[str, str]:
    """Auto-detect text column and label column."""
    text_col  = None
    label_col = None

    # Text column candidates (in priority order)
    for candidate in ["Prompt", "prompt", "text", "message", "content", "input"]:
        if candidate in df.columns:
            text_col = candidate
            break

    # Label column candidates
    for candidate in ["isMalicious", "label", "is_malicious", "malicious", "class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if text_col is None or label_col is None:
        raise ValueError(
            f"Could not detect text/label columns. Got: {df.columns.tolist()}"
        )
    return text_col, label_col


def normalize_label(raw) -> str:
    """Map raw label to VALID / INVALID."""
    if isinstance(raw, (int, float)):
        return LABEL_MAP.get(int(raw), "INVALID")
    s = str(raw).strip().lower()
    if s in ("0", "benign", "safe", "valid", "ham"):
        return "VALID"
    return "INVALID"


def main() -> None:
    print("=" * 60)
    print("Stage 3 — MPDD Data Preprocessor")
    print("=" * 60)

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    print(f"[INFO] Reading: {INPUT_FILE}")
    df = pd.read_csv(INPUT_FILE)
    print(f"[INFO] Rows loaded: {len(df)}")

    text_col, label_col = detect_columns(df)
    print(f"[INFO] Text column  : '{text_col}'")
    print(f"[INFO] Label column : '{label_col}'")

    # Keep only needed columns, rename to standard names
    df = df[[text_col, label_col]].copy()
    df.columns = ["text", "raw_label"]

    # Drop NaN rows
    before = len(df)
    df.dropna(subset=["text", "raw_label"], inplace=True)
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() >= 5]
    print(f"[INFO] After cleaning: {len(df)} rows (dropped {before - len(df)})")

    # Map labels
    df["label"] = df["raw_label"].apply(normalize_label)
    df.drop(columns=["raw_label"], inplace=True)

    # Label distribution
    dist = df["label"].value_counts()
    print("[INFO] Label distribution:")
    for lbl, cnt in dist.items():
        print(f"         {lbl}: {cnt} ({cnt/len(df)*100:.1f}%)")

    # -- Stratified train/test split (split BEFORE any fitting) -----------
    train_df, test_df = train_test_split(
        df,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["label"],
        shuffle=True,
    )

    print(f"[INFO] Train set : {len(train_df)} rows")
    print(f"[INFO] Test  set : {len(test_df)} rows")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    train_df.to_csv(TRAIN_FILE, index=False, encoding='utf-8')
    test_df.to_csv(TEST_FILE, index=False, encoding='utf-8')

    print(f"[OK]   Saved train -> {TRAIN_FILE}")
    print(f"[OK]   Saved test  -> {TEST_FILE}")


if __name__ == "__main__":
    main()
