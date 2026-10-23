# Sentinel-ML — Model Specifications & Distribution Guide

This document catalogs the production model artifacts required for offline evaluation and mobile inference, detailing file formats, cryptographic hashes, loading procedures, and distribution strategies.

---

## 1. Production Model Catalog

### 1.1 URL Threat Classifier Models

| Artifact | Location | Size | Format | SHA-256 Checksum | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `v8_champion.joblib` | `URL-ml/models/v8_champion.joblib` | 1.2 MB | Joblib / Scikit-Learn | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | Python offline evaluation & benchmark reference. |
| `v8_champion_portable.json` | `URL-ml/models/v8_champion_portable.json` | 850 KB | JSON (Tree nodes & bins) | `e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870` | Pure-Kotlin on-device mobile inference (Android runtime asset). |
| `v8_parent_profiles.json` | `URL-ml/models/v8_parent_profiles.json` | 21 MB | JSON | — | Brand and domain reputation profiles used in adjudication. |

### 1.2 Messages Threat Classifier Models

| Artifact | Location | Size | Format | SHA-256 Checksum (Prefix) | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `champion_model.pkl` | `Messages-ml/champion_model.pkl` | 1.54 MB | Pickle (ExtraTrees) | `a85c6df7...` | Python reference Messages V4 classifier. |
| `champion_scaler.pkl` | `Messages-ml/champion_scaler.pkl` | 50 KB | Pickle (StandardScaler) | `37d44697...` | Feature scaling parameters. |
| `champion_tfidf.pkl` | `Messages-ml/champion_tfidf.pkl` | 78 KB | Pickle (TF-IDF Vectorizer) | `b6bfd4cf...` | Dual n-gram vocabulary and IDF weights. |
| `champion_v2_model.pkl` | `Messages-ml/champion_v2_model.pkl` | 1.78 MB | Pickle (ExtraTrees V2) | `4c8dcfca...` | Messages V4.5 / candidate classifier. |
| `champion_v2_trees.json` | `android-runtime/messages/assets/champion_v2_trees.json` | 1.1 MB | JSON | — | Kotlin tree traversal asset for Android. |
| `champion_v2_word_vocab_idf.json` | `android-runtime/messages/assets/champion_v2_word_vocab_idf.json` | 45 KB | JSON | — | Word token vocabulary and weights. |
| `champion_v2_char_vocab_idf.json` | `android-runtime/messages/assets/champion_v2_char_vocab_idf.json` | 15 KB | JSON | — | Character n-gram vocabulary and weights. |

---

## 2. Model Loading & Inference Procedures

### 2.1 Python Offline Inference (URL-ML)

```python
import joblib
from pathlib import Path
from URL-ml.scripts.v8_features import extract_v8_features
from URL-ml.scripts.v8_classifier import V8RelationalURLClassifier

# 1. Load model artifact
model_path = Path("URL-ml/models/v8_champion.joblib")
raw_hgb_model = joblib.load(model_path)

# 2. Instantiate relational adjudicator
classifier = V8RelationalURLClassifier(base_model=raw_hgb_model)

# 3. Predict on URL
url = "https://example-phishing-login.com"
result = classifier.predict(url)
print(f"Verdict: {result.verdict}, Threat Probability: {result.prob:.4f}")
```

### 2.2 Python Offline Inference (Messages-ML)

```python
import pickle
from pathlib import Path

# Load vectorizer and classifier
with open("Messages-ml/champion_model.pkl", "rb") as f:
    model = pickle.load(f)
with open("Messages-ml/champion_tfidf.pkl", "rb") as f:
    tfidf = pickle.load(f)

# Predict message class
text = "Dear customer, your bank account has been suspended. Click here to verify."
vec = tfidf.transform([text])
prediction = model.predict(vec)[0]  # Returns 'BENIGN', 'SPAM', or 'MALICIOUS'
print(f"Message Threat Class: {prediction}")
```

### 2.3 Android On-Device Inference (Pure Kotlin)

The mobile Android runtime does **not** load `.pkl` or `.joblib` files. Instead, it reads the portable JSON bundles from Android assets:

```kotlin
// Loaded from assets/v8_champion_portable.json
val treeEvaluator = HistGbmTreeEvaluator.fromAsset(context, "v8_champion_portable.json")
val featureVector = V8FeatureExtractor.extract(url)
val rawProbability = treeEvaluator.predictProbability(featureVector)
val verdict = SafeDomainAdjudicator.adjudicate(url, rawProbability)
```

---

## 3. Safe Model Distribution Recommendations

Binary model serialization formats (`.pkl`, `.joblib`) are excluded from normal Git commits by default via `.gitignore` to prevent repository bloat and mitigate arbitrary-code-execution security risks associated with deserializing untrusted Python pickle files.

### Recommended Distribution Methods:

1. **Lightweight Portable JSON (Included in Repository)**:
   - The portable JSON models (`v8_champion_portable.json`, `champion_v2_*.json`) are human-readable, auditable text files under 1 MB.
   - These are fully tracked by Git and sufficient to run the mobile evaluator or golden tests immediately upon cloning.

2. **GitHub Releases for Binary Artifacts**:
   - For offline Python training and evaluation, attach `v8_champion.joblib` and `champion_model.pkl` to a tagged GitHub Release (e.g., `v1.0.0-models`).
   - Publish SHA-256 checksums in the release notes so downstream users can verify binary integrity before loading.

3. **Git LFS (Large File Storage) Alternative**:
   - If binary models must reside directly within the git repository for automated CI, configure Git LFS:
     ```bash
     git lfs track "URL-ml/models/*.joblib"
     git lfs track "Messages-ml/*.pkl"
     ```
