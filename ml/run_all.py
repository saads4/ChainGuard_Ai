"""
ChainGuardAI ML Pipeline — Master Orchestrator
===============================================
One-shot pipeline: preprocess -> train -> evaluate

Usage:
    python ml/run_all.py            # full pipeline
    python ml/run_all.py --skip-s2  # skip Stage 2 embedding (slow GPU step)
    python ml/run_all.py --eval-only # skip training, run evaluation only

Steps:
  1. stage2_benign_prep    — extract benign texts from Stage_2.jsonl
  2. stage3_mpdd_prep      — split MPDD.csv -> train/test  
  3. attack_sim_merge      — merge attack CSVs -> wild_attacks.csv
  4. train_stage2_baseline — compute embedding centroid
  5. train_stage3_classifier — train TF-IDF + LogReg
  6. build_action_gate     — build rule table from action_dataset.csv
  7. evaluate_pipeline     — evaluate on wild_attacks (quick, 500 rows)
"""

import argparse
import importlib
import subprocess
import sys
import time
from pathlib import Path

# -- Paths --------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ML_DIR       = PROJECT_ROOT / "ml"

# -- Rich console (graceful fallback) -----------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

STEPS = [
    {
        "name":   "Stage 2 — Benign Prep",
        "module": "ml.preprocess.stage2_benign_prep",
        "tag":    "preprocess",
    },
    {
        "name":   "Stage 3 — MPDD Prep",
        "module": "ml.preprocess.stage3_mpdd_prep",
        "tag":    "preprocess",
    },
    {
        "name":   "Attack Sim — Merge",
        "module": "ml.preprocess.attack_sim_merge",
        "tag":    "preprocess",
    },
    {
        "name":   "Stage 2 — Train Embedding Baseline",
        "module": "ml.train.train_stage2_baseline",
        "tag":    "train_s2",
    },
    {
        "name":   "Stage 3 — Train Intent Classifier",
        "module": "ml.train.train_stage3_classifier",
        "tag":    "train_s3",
    },
    {
        "name":   "Action Gate — Build Rules",
        "module": "ml.train.build_action_gate",
        "tag":    "train",
    },
    {
        "name":   "Evaluation — Wild Attacks (500 rows)",
        "module": "ml.evaluate.evaluate_pipeline",
        "tag":    "eval",
    },
]


def print_header() -> None:
    msg = (
        "\n"
        "  ╔══════════════════════════════════════════════╗\n"
        "  ║   ChainGuardAI ML Pipeline — run_all.py       ║\n"
        "  ║   Preprocess -> Train -> Evaluate              ║\n"
        "  ╚══════════════════════════════════════════════╝\n"
    )
    print(msg)


def run_step(step: dict, step_num: int, total: int) -> tuple[bool, float]:
    """Run one pipeline step via subprocess to guarantee clean state."""
    module = step["module"]
    label  = step["name"]
    script = str(PROJECT_ROOT / module.replace(".", "/") + ".py")

    print(f"\n[{step_num}/{total}] {label}")
    print(f"       {'-' * 50}")

    t0 = time.time()
    result = subprocess.run(
        [sys.executable, script],
        cwd=str(PROJECT_ROOT),
        capture_output=False,   # stream output directly
    )
    elapsed = time.time() - t0
    ok = result.returncode == 0

    status = "[OK]  DONE" if ok else "[FAIL]  FAILED"
    print(f"\n       {status}  ({elapsed:.1f}s)")
    return ok, elapsed


def main() -> None:
    parser = argparse.ArgumentParser(description="ChainGuardAI ML Pipeline")
    parser.add_argument("--skip-s2",   action="store_true",
                        help="Skip Stage 2 embedding training (saves time, needs GPU)")
    parser.add_argument("--eval-only", action="store_true",
                        help="Skip all training, run evaluation only")
    parser.add_argument("--eval-rows", type=int, default=500,
                        help="Number of attack rows for quick eval (default: 500)")
    args = parser.parse_args()

    print_header()

    steps = STEPS.copy()

    # Filter steps based on flags
    if args.eval_only:
        steps = [s for s in steps if s["tag"] == "eval"]
    if args.skip_s2:
        steps = [s for s in steps if s["tag"] != "train_s2"]

    results = []
    total_t0 = time.time()

    for i, step in enumerate(steps, 1):
        ok, elapsed = run_step(step, i, len(steps))
        results.append({
            "step":    step["name"],
            "status":  "OK" if ok else "FAILED",
            "elapsed": elapsed,
        })
        if not ok and step["tag"] not in ("eval",):
            print(f"\n[STOP]  Step failed — halting pipeline. Fix the error above and re-run.")
            break

    total_elapsed = time.time() - total_t0

    # -- Final Summary ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("  PIPELINE SUMMARY")
    print("=" * 60)
    n_ok     = sum(1 for r in results if r["status"] == "OK")
    n_failed = sum(1 for r in results if r["status"] == "FAILED")

    for r in results:
        icon = "[OK]" if r["status"] == "OK" else "[FAIL]"
        print(f"  {icon}  {r['step']:<40}  {r['elapsed']:5.1f}s")

    print(f"\n  Completed: {n_ok}/{len(results)} steps  |  Total time: {total_elapsed:.1f}s")

    if n_failed == 0:
        print("\n[OK]  All pipeline steps completed successfully!")
        print("    Next: python pipeline_demo.py")
    else:
        print(f"\n[WARN]   {n_failed} step(s) failed. Check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
