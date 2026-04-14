"""
Action Gate Rule Builder
==========================
Reads dataset/action_log/action_dataset.csv (44 rows).
Builds:
  1. Rule-based thresholds: (action, parameter, value) -> risk_score + decision
  2. Optional secondary ML classifier (LogReg on categorical features)

Decisions:
  risk_score < 0.40   -> ALLOW
  0.40 <= score < 0.75 -> REVIEW
  score >= 0.75        -> BLOCK

Saves:
  data/models/action_gate/thresholds.json   — rule lookup table
  data/models/action_gate/classifier.pkl    — secondary ML model
  data/models/action_gate/metadata.json     — build info
"""

import json
import pickle
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.pipeline import Pipeline

# -- Resolve project root ----------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE   = PROJECT_ROOT / "dataset" / "action_log" / "action_dataset.csv"
OUTPUT_DIR   = PROJECT_ROOT / "data" / "models" / "action_gate"

THRESHOLDS = {"ALLOW": 0.40, "REVIEW": 0.75}   # [0, 0.40) ALLOW | [0.40, 0.75) REVIEW | [0.75, 1] BLOCK


def risk_to_decision(score: float) -> str:
    if score < THRESHOLDS["ALLOW"]:
        return "ALLOW"
    elif score < THRESHOLDS["REVIEW"]:
        return "REVIEW"
    return "BLOCK"


def build_rule_table(df: pd.DataFrame) -> dict:
    """Build nested rule lookup: action -> parameter -> value -> {risk_score, decision}."""
    rules: dict = {}

    for _, row in df.iterrows():
        action    = str(row.get("action", "UNKNOWN")).strip()
        parameter = str(row.get("parameter", "UNKNOWN")).strip()
        value     = str(row.get("value", "")).strip()
        label     = str(row.get("label", "")).strip()
        try:
            risk_score = float(row.get("risk_score", 0.5))
        except (ValueError, TypeError):
            risk_score = 0.5

        decision = label if label in ("SAFE", "REVIEW", "BLOCK") else risk_to_decision(risk_score)
        # Normalize SAFE -> ALLOW
        if decision == "SAFE":
            decision = "ALLOW"

        if action not in rules:
            rules[action] = {}
        if parameter not in rules[action]:
            rules[action][parameter] = {}

        rules[action][parameter][value] = {
            "risk_score": round(risk_score, 4),
            "decision":   decision,
        }

    return rules


def build_secondary_classifier(df: pd.DataFrame):
    """Train a simple Logistic Regression as fallback when rule lookup misses."""
    # Feature: "action__context"
    X_raw = (df["action"].astype(str) + "__" + df["context"].astype(str)).tolist()
    y_raw = df["label"].str.replace("SAFE", "ALLOW").tolist()

    le_y = LabelEncoder().fit(y_raw)
    y_enc = le_y.transform(y_raw)

    le_x = LabelEncoder().fit(X_raw)
    X_enc = le_x.transform(X_raw).reshape(-1, 1)

    clf = LogisticRegression(max_iter=500, random_state=42, class_weight="balanced")
    clf.fit(X_enc, y_enc)

    return clf, le_x, le_y


def annotate_action(action: dict, parameter: str, value, risk_score: float) -> str:
    """
    Runtime helper — exposed as standalone function so pipeline_demo.py can call it.
    Returns ALLOW / REVIEW / BLOCK.
    """
    decision = risk_to_decision(risk_score)
    return decision


def main() -> None:
    print("=" * 60)
    print("Action Gate — Rule Builder")
    print("=" * 60)

    if not INPUT_FILE.exists():
        print(f"[ERROR] Input not found: {INPUT_FILE}")
        sys.exit(1)

    df = pd.read_csv(INPUT_FILE, skip_blank_lines=True)
    df.dropna(subset=["action", "parameter"], inplace=True)
    df["label"] = df["label"].str.strip().str.upper()
    print(f"[INFO] Loaded {len(df)} action records")

    # -- 1. Rule table --------------------------------------------------------
    print("[INFO] Building rule table ...")
    rules = build_rule_table(df)

    total_rules = sum(
        len(vals)
        for params in rules.values()
        for vals in params.values()
    )
    print(f"[INFO] Actions: {len(rules)} | Total rule entries: {total_rules}")

    # -- 2. Secondary ML classifier -------------------------------------------
    print("[INFO] Training secondary ML classifier ...")
    clf, le_x, le_y = build_secondary_classifier(df)
    print(f"       Classes: {le_y.classes_.tolist()}")

    # -- 3. Risk distribution summary -----------------------------------------
    dist = df["label"].value_counts()
    print("[INFO] Rule-label distribution:")
    for lbl, cnt in dist.items():
        decision = "ALLOW" if lbl == "SAFE" else lbl
        print(f"         {lbl:>6} -> {decision}: {cnt}")

    # -- 4. Save --------------------------------------------------------------
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    thresholds_payload = {
        "decision_thresholds": THRESHOLDS,
        "block_threshold": THRESHOLDS["REVIEW"],
        "rules": rules,
    }
    with open(OUTPUT_DIR / "thresholds.json", "w") as fh:
        json.dump(thresholds_payload, fh, indent=2)

    with open(OUTPUT_DIR / "classifier.pkl", "wb") as fh:
        pickle.dump({"model": clf, "le_x": le_x, "le_y": le_y}, fh)

    metadata = {
        "total_rules":    total_rules,
        "actions":        list(rules.keys()),
        "thresholds":     THRESHOLDS,
        "timestamp":      datetime.utcnow().isoformat() + "Z",
        "source":         INPUT_FILE.name,
    }
    with open(OUTPUT_DIR / "metadata.json", "w") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"\n[OK]   thresholds.json -> {OUTPUT_DIR / 'thresholds.json'}")
    print(f"[OK]   classifier.pkl  -> {OUTPUT_DIR / 'classifier.pkl'}")
    print(f"[OK]   metadata.json   -> {OUTPUT_DIR / 'metadata.json'}")

    # -- 5. Quick sanity check -------------------------------------------------
    print("\n[INFO] Sanity checks:")
    checks = [
        ("stripe_charge", "amount", "50000", "BLOCK"),
        ("file_write",    "path",   "/etc/passwd", "BLOCK"),
        ("shell_exec",    "command", "ls", "ALLOW"),
        ("db_query",      "query_type", "DELETE", "REVIEW"),
    ]
    for action, param, val, expected in checks:
        entry = rules.get(action, {}).get(param, {}).get(val)
        if entry:
            result = entry["decision"]
            status = "[OK]" if result == expected else "[FAIL]"
            print(f"  {status} {action}({param}={val}) -> {result} (expected {expected})")
        else:
            print(f"  [WARN]  Rule not found: {action}({param}={val})")


if __name__ == "__main__":
    main()
