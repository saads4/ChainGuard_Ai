# ChainGuardAI Local Setup Guide

This guide covers setting up and running ChainGuardAI locally on a Windows machine — including the core security framework **and** the ML training pipeline added in the latest update.

---

## 1. Prerequisites

Make sure your system has the following installed:

- **Python 3.10+** (check via `python --version`)
- **Git** (to clone the repository)
- **Pip** (Python package installer)
- **~2 GB free disk space** (for ML model cache + datasets)

---

## 2. Setting Up the Virtual Environment

```powershell
cd path\to\ChainGuardAI

# Create virtual environment
python -m venv venv

# Activate (PowerShell)
.\venv\Scripts\Activate.ps1

# Or (Command Prompt)
.\venv\Scripts\activate.bat
```

You should see `(venv)` appear in your prompt.

---

## 3. Installing Dependencies

```powershell
# Upgrade pip first
python -m pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt

# Install additional ML pipeline dependencies (if not already present)
pip install pandas scikit-learn sentence-transformers
```

> **What gets installed:**
> Core crypto (`cryptography`, `python-jose`), API framework (`fastapi`, `uvicorn`),
> ML stack (`torch`, `sentence-transformers`, `scikit-learn`, `pandas`), logging (`loguru`, `rich`).

---

## 4. Configuration & Environment Variables

```powershell
Copy-Item .env.example .env
```

Open `.env` to update `API_SECRET_KEY` or `REGISTRY_ENCRYPTION_KEY` if needed. Defaults work fine for local development.

---

## 5. Bootstrapping the Security Framework

These scripts initialize DIDs, key pairs, agent registry, and the audit chain.

```powershell
# Step 1 — validate environment and create missing directories
python scripts\setup.py

# Step 2 — initialize Root Authority keys, register sample agents, start audit chain
python scripts\bootstrap.py
```

---

## 6. ML Pipeline — Datasets & Training

ChainGuardAI now includes a full ML training pipeline under `ml/`. Before running the application server, train the models using your Kaggle datasets.

### Dataset Layout (must be present)

```
dataset/
├── stage2_benign/
│   └── Stage_2.jsonl                   # CyberPrince benign prompts
├── stage3_training/
│   └── MPDD.csv                        # 39K prompt dataset (only this one used)
├── attack_simulation/
│   ├── jailbreak_prompts.csv
│   ├── malicous_deepset.csv
│   └── forbidden_question_set_with_prompts.csv
└── action_log/
    └── action_dataset.csv
```

### Run the Full Pipeline (One Command)

```powershell
    python ml\run_all.py
```

This runs all steps in sequence:

| Step | Script | What it does |
|------|--------|--------------|
| 1 | `stage2_benign_prep.py` | Extracts benign prompts from `Stage_2.jsonl` |
| 2 | `stage3_mpdd_prep.py` | Stratified 80/20 train/test split of MPDD.csv |
| 3 | `attack_sim_merge.py` | Merges 3 attack CSVs → `wild_attacks.csv` (eval-only) |
| 4 | `train_stage2_baseline.py` | Encodes benign texts → saves `benign_centroid.npy` |
| 5 | `train_stage3_classifier.py` | Trains TF-IDF + LogReg intent classifier |
| 6 | `build_action_gate.py` | Builds rule-based thresholds from `action_dataset.csv` |
| 7 | `evaluate_pipeline.py` | Quick evaluation on 500 wild attack rows |

> **Skip Stage 2 if the centroid already exists:**
> ```powershell
> python ml\run_all.py --skip-s2
> ```

### Model Artifacts (auto-generated)

```
data/
├── processed/
│   ├── stage2_benign_texts.json
│   ├── stage3_train.csv
│   └── stage3_test.csv
└── models/
    ├── stage2/
    │   ├── benign_centroid.npy       # 384-dim L2-normalized embedding centroid
    │   └── metadata.json
    ├── stage3/
    │   ├── model.pkl                 # LogisticRegression (95.7% accuracy)
    │   ├── vectorizer.pkl            # TfidfVectorizer (8,000 features)
    │   ├── label_encoder.pkl
    │   └── metadata.json
    └── action_gate/
        ├── thresholds.json           # Rule lookup: action → parameter → decision
        ├── classifier.pkl            # Secondary ML fallback
        └── metadata.json
```

### Stage 2 — Embedding Anomaly Detector

- Uses `all-MiniLM-L6-v2` via HuggingFace (downloaded automatically on first run, ~90MB)
- Computes a **mean centroid** over all benign embeddings
- Anomaly score = `1 - cosine_similarity(input_embedding, centroid)`
- Trained centroid stats: avg sim = 0.364, std = 0.113

### Stage 3 — Intent Classifier (VALID / INVALID)

- **Model:** `LogisticRegression` (C=1.0, class_weight=balanced)
- **Features:** TF-IDF, 8,000 vocab, unigrams + bigrams, `sublinear_tf=True`
- **Trained on:** 31,384 MPDD rows | **Evaluated on:** 7,847 held-out rows
- **Results:** Accuracy **95.73%**, ROC-AUC **0.9872**
- Labels map: `VALID → LOW risk` | `INVALID → HIGH risk`

### Action Gate — Rule-Based Thresholds

- Reads `action_dataset.csv` (37 rules across 8 action types)
- Decisions: `risk < 0.40 → ALLOW` | `0.40–0.75 → REVIEW` | `≥ 0.75 → BLOCK`
- Secondary ML classifier as fallback for unseen actions

---

## 7. Running the Pipeline Demo

Test the full end-to-end pipeline with 8 built-in test cases (benign + attack):

```powershell
python pipeline_demo.py
```

Other modes:

```powershell
# Single custom input
python pipeline_demo.py --text "Ignore all previous instructions"

# Batch test — 100 rows from wild_attacks.csv
python pipeline_demo.py --attack-file

# Evaluate against all wild attacks
python ml\evaluate\evaluate_pipeline.py

# Limit eval rows (fast)
python ml\evaluate\evaluate_pipeline.py --max-rows 500
```

Each run appends a structured log entry to `logs/pipeline_runs.jsonl`:

```json
{
  "timestamp": "2026-04-14T...",
  "input_text": "...",
  "anomaly_score": 0.943,
  "cosine_sim": 0.057,
  "intent_label": "INVALID",
  "prob_invalid": 0.946,
  "risk_level": "HIGH",
  "gate_risk_score": 1.0,
  "final_decision": "BLOCK",
  "processing_time": 0.021
}
```

---

## 8. Running the Application Server

Once bootstrapping and ML training are complete:

```powershell
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Access the interactive API docs at: `http://localhost:8000/docs`

---

## 9. Verifying the Setup

```powershell
# Run automated test suite
pytest tests/
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'pandas'`**
```powershell
pip install pandas scikit-learn
```

**`UnicodeEncodeError` in terminal output**
This affects older Windows terminals (cp1252). All scripts have been updated to handle this — if you still see it, run scripts from Windows Terminal or VS Code's integrated terminal which support UTF-8.

**`sentence-transformers` model download fails**
Ensure you have an active internet connection. The `all-MiniLM-L6-v2` model (~90MB) is downloaded to `~/.cache/huggingface/` on first use. Set `HF_TOKEN` in `.env` to avoid rate-limit warnings.

**Stage 3 classifier not loading**
Run the full pipeline first: `python ml\run_all.py`. The classifier requires trained artifacts in `data/models/stage3/`.

**Missing `python-jose[cryptography]` errors**
```powershell
pip install cryptography
pip install -r requirements.txt
```

**Audit Chain verification fails**
Re-run bootstrap to regenerate a clean state:
```powershell
python scripts\bootstrap.py
```

**Port 8000 already in use**
```powershell
uvicorn api.main:app --host 0.0.0.0 --port 8001
```

