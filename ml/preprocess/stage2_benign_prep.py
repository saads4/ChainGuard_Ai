"""
Stage 2 Benign Data Preprocessor
==================================
Parses dataset/stage2_benign/Stage_2.jsonl (CyberPrince dataset).
Extracts only 'benign' labeled entries, normalizes text, deduplicates,
and saves to data/processed/stage2_benign_texts.json.

Output format: {"texts": [...], "count": N, "source": "Stage_2.jsonl"}
"""

import json
import re
import sys
from pathlib import Path

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE   = PROJECT_ROOT / "dataset" / "stage2_benign" / "Stage_2.jsonl"
OUTPUT_DIR   = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE  = OUTPUT_DIR / "stage2_benign_texts.json"


def clean_text(text: str) -> str:
    """Normalize text: strip, collapse whitespace, but keep case."""
    text = text.strip()
    text = re.sub(r"\s+", " ", text)   # collapse multiple spaces/newlines
    return text


def load_benign_prompts(jsonl_path: Path) -> list[str]:
    """Read JSONL and extract benign prompts only."""
    texts = []
    skipped = 0

    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for line_num, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [WARN] Line {line_num}: JSON parse error — {e}")
                skipped += 1
                continue

            label = record.get("label", "").lower()
            if label != "benign":
                continue  # skip malicious / unknown entries

            # Primary text field is 'prompt'; fall back to other keys
            text = (
                record.get("prompt")
                or record.get("text")
                or record.get("content")
                or ""
            )
            text = clean_text(str(text))
            if len(text) >= 5:          # drop trivially short strings
                texts.append(text)

    return texts


def deduplicate(texts: list[str]) -> list[str]:
    """Remove exact duplicates while preserving order."""
    seen = set()
    unique = []
    for t in texts:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def main() -> None:
    print("=" * 60)
    print("Stage 2 — Benign Data Preprocessor")
    print("=" * 60)

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    print(f"[INFO] Reading: {INPUT_FILE}")
    texts = load_benign_prompts(INPUT_FILE)
    print(f"[INFO] Benign entries extracted : {len(texts)}")

    texts = deduplicate(texts)
    print(f"[INFO] After deduplication      : {len(texts)}")

    if len(texts) == 0:
        print("[ERROR] No benign texts found — check 'label' field in JSONL.")
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "texts":  texts,
        "count":  len(texts),
        "source": INPUT_FILE.name,
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    print(f"[OK]   Saved {len(texts)} benign texts -> {OUTPUT_FILE}")
    print(f"       Sample:")
    for t in texts[:3]:
        print(f"         * {t[:100]}")


if __name__ == "__main__":
    main()
