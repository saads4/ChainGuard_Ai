"""
Attack Simulation Dataset Merger
==================================
Merges three attack CSV files from dataset/attack_simulation/:
  - jailbreak_prompts.csv          (text col: 'prompt')
  - malicous_deepset.csv           (text col: 'Prompt')
  - forbidden_question_set_with_prompts.csv (text col: 'Prompt')

Normalises all text into a single 'text' column.
Labels ALL rows as 'ATTACK'.
Deduplicates, drops NaN, saves to dataset/attack_simulation/wild_attacks.csv.

[WARN]️  This dataset is NEVER used for training — evaluation only.
"""

import sys
import pandas as pd
from pathlib import Path

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT   = Path(__file__).resolve().parents[2]
ATK_DIR        = PROJECT_ROOT / "dataset" / "attack_simulation"
OUTPUT_FILE    = ATK_DIR / "wild_attacks.csv"

# Max rows to sample from large files (keeps processing fast)
MAX_JAILBREAK  = 20_000
MAX_DEEPSET    = None        # small, use all
MAX_FORBIDDEN  = 50_000

SOURCES = [
    {
        "file":      ATK_DIR / "jailbreak_prompts.csv",
        "text_cols": ["prompt", "Prompt", "text", "content"],
        "max_rows":  MAX_JAILBREAK,
        "name":      "jailbreak_prompts",
    },
    {
        "file":      ATK_DIR / "malicous_deepset.csv",
        "text_cols": ["Prompt", "prompt", "text", "content"],
        "max_rows":  MAX_DEEPSET,
        "name":      "malicous_deepset",
    },
    {
        "file":      ATK_DIR / "forbidden_question_set_with_prompts.csv",
        "text_cols": ["Prompt", "prompt", "text", "content"],
        "max_rows":  MAX_FORBIDDEN,
        "name":      "forbidden_questions",
    },
]


def find_text_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return first matching candidate column or None."""
    for col in candidates:
        if col in df.columns:
            return col
    return None


def load_source(source: dict) -> pd.DataFrame | None:
    """Load one source file; returns DataFrame with ['text', 'source'] or None."""
    path = source["file"]
    name = source["name"]

    if not path.exists():
        print(f"  [WARN] File not found, skipping: {path.name}")
        return None

    print(f"  [INFO] Loading {path.name} ...", end=" ", flush=True)
    try:
        # Read with nrows if max_rows set
        df = pd.read_csv(path, nrows=source["max_rows"], encoding="utf-8",
                         on_bad_lines="skip")
    except UnicodeDecodeError:
        df = pd.read_csv(path, nrows=source["max_rows"], encoding="latin-1",
                         on_bad_lines="skip")

    text_col = find_text_column(df, source["text_cols"])
    if text_col is None:
        print(f"\n  [WARN] No text column found in {path.name}. Cols: {df.columns.tolist()}")
        return None

    result = pd.DataFrame({
        "text":   df[text_col].astype(str).str.strip(),
        "source": name,
    })
    print(f"{len(result):,} rows")
    return result


def main() -> None:
    print("=" * 60)
    print("Attack Simulation — Dataset Merger")
    print("=" * 60)

    frames = []
    for src in SOURCES:
        df = load_source(src)
        if df is not None:
            frames.append(df)

    if not frames:
        print("[ERROR] No source files could be loaded.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[INFO] Combined rows (pre-clean): {len(combined):,}")

    # Clean
    combined["text"] = combined["text"].str.strip()
    combined.dropna(subset=["text"], inplace=True)
    combined = combined[combined["text"].str.len() >= 5]
    combined = combined[combined["text"] != "nan"]

    # Deduplicate on text
    before = len(combined)
    combined.drop_duplicates(subset=["text"], inplace=True)
    print(f"[INFO] After dedup     : {len(combined):,} rows (dropped {before - len(combined):,})")

    # Label all as ATTACK
    combined["label"] = "ATTACK"

    # Source breakdown
    print("[INFO] Source breakdown:")
    for src, cnt in combined["source"].value_counts().items():
        print(f"         {src}: {cnt:,}")

    # Save
    ATK_DIR.mkdir(parents=True, exist_ok=True)
    combined[["text", "label", "source"]].to_csv(OUTPUT_FILE, index=False, encoding="utf-8")
    print(f"\n[OK]   wild_attacks.csv -> {OUTPUT_FILE}")
    print(f"       Total ATTACK samples: {len(combined):,}")
    print(f"\n  Sample rows:")
    for _, row in combined.head(3).iterrows():
        print(f"    [{row['source']}] {row['text'][:90]}")


if __name__ == "__main__":
    main()
