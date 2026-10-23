# Sentinel-ML — GitHub Preparation & Repository Readiness Report

**Document Version:** 1.0.0  
**Date:** October 23, 2026  
**Auditor:** Antigravity Autonomous Systems Specialist  
**Status:** **READY FOR MANUAL GIT INITIALIZATION & REPOSITORY PUSH**  
**Git Governance Invariant:** Zero Git commands were executed (`git init`, `git status`, `git add`, `git commit`, `git push`, `git rm`, etc. were strictly omitted).

---

## 1. Original Folder Structure

Prior to this preparation procedure, the parent workspace contained an uninitialized machine learning directory (`sentinel-ml`) alongside the independent Android Git repository (`sentinel-ai`), workspace documentation folders, and an empty nested `.git` stub inside `sentinel-ml/URL-ml/`:

```text
Sentinel/
├── .pytest_cache/                                # Workspace-level test cache
├── assistant_review_20261023/                    # Independent analyst review dossiers
├── backup_nested_git/                            # [NEW] Backup of nested Git metadata
├── docs/                                         # Workspace-level architecture documentation
├── reports/                                      # Cross-project sprint logs & audits
├── research/                                     # Research notes and methodologies
├── sentinel-ai/                                  # [PROTECTED] Production Android Git repository
├── tools/                                        # Shared workspace verification tools
├── README.md                                     # Workspace-level navigation guide
└── sentinel-ml/                                  # Machine learning subsystem
    ├── .pytest_cache/
    ├── 6sep/                                     # Historical optimization manifests
    ├── 7sep_messages_v3/                         # Replay datasets & baseline models
    ├── android-runtime/                          # Portable JSON runtime models & Kotlin tools
    ├── archive/                                  # Historical models & dataset archives
    ├── Databases/                                # SQLite threat intelligence databases
    ├── investigation/                            # Forensic recovery scripts & database parsers
    ├── Messages-ml/                              # SMS/WhatsApp threat classifier subsystem
    │   ├── .pytest_cache/
    │   ├── data/
    │   ├── model/
    │   ├── reports/
    │   ├── scripts/
    │   └── tests/
    ├── New_history/                              # Device replay message history logs
    ├── scratch/                                  # Scratch scripts, ablation studies, test jars
    ├── URL-ml/                                   # URL threat classifier subsystem
    │   ├── .agents/                              # Empty agent cache folder
    │   ├── .git/                                 # [NESTED METADATA] Empty stub directory
    │   ├── data/
    │   ├── docs/
    │   ├── experiments/
    │   ├── model/
    │   ├── models/
    │   ├── reports/
    │   ├── scripts/
    │   ├── tests/
    │   └── venv/
    ├── FINAL_ANDROID_DEPLOYMENT_READINESS.md     # Mobile deployment readiness record
    ├── MESSAGES_V4_FINAL_REPORT.md               # Messages V4 performance report
    ├── MESSAGES_V4_FORENSIC_BASELINE.md          # Baseline forensic audit
    ├── MESSAGES_V4_RELEASE_DECISION.json         # Structured release decision ledger
    └── V3_ARCHITECTURE_AUDIT.md                  # Historical V3 architecture audit
```

---

## 2. Final Folder Structure

The organized `sentinel-ml` repository structure preserves all working code, models, and relative dependencies while introducing standardized top-level directories (`shared/`, `scripts/`, `docs/`, `reports/`, `.gitignore`, `README.md`):

```text
sentinel-ml/
├── .gitignore                                    # [NEW] Comprehensive ML Git exclusion rules
├── README.md                                     # [NEW] Master Sentinel-ML documentation
├── GITHUB_PREPARATION_REPORT.md                  # [NEW] This readiness & preparation report
│
├── docs/                                         # [NEW] High-level ML subsystem documentation
│   ├── ARCHITECTURE.md                           # ML architecture & Risk Fusion Engine guide
│   ├── MODEL_SPECIFICATIONS.md                   # Model catalog, input/output schemas & distribution
│   ├── RESEARCH_NOTES.md                         # [MOVED from research/README.md] Threat taxonomies & governance
│   ├── WORKSPACE_ARCHITECTURE.md                 # [MOVED from docs/WORKSPACE_ARCHITECTURE.md] Cross-tier contracts
│   └── WORKSPACE_ROOT_README.md                  # [COPIED from Sentinel/README.md] Preserved workspace overview
│
├── reports/                                      # [NEW] Index of ML evaluation & forensic audits
│   ├── README.md                                 # Directory index of audit dossiers
│   ├── WORKSPACE_ORGANIZATION_REPORT.md          # [MOVED from reports/WORKSPACE_ORGANIZATION_REPORT.md] Prior audit
│   ├── dev_sprint_01/                            # [MOVED from reports/dev_sprint_01] Messages-ML sprint evaluations
│   ├── url_sprint_01/                            # [MOVED from reports/url_sprint_01] URL-ML sprint evaluations & gates
│   ├── simulation_diagnosis/                     # [MOVED from reports/simulation_diagnosis] ML simulation traces
│   └── assistant_review_20261023/                # [MOVED from assistant_review_20261023] Independent analyst reviews
│
├── shared/                                       # [NEW] Shared protocols and data contracts
│   ├── contracts.py                              # Severity, class enums & dataclass contracts
│   └── README.md                                 # Contract usage and architecture guide
│
├── scripts/                                      # [NEW] Repository verification utilities
│   ├── README.md                                 # [MOVED from tools/README.md] Tooling boundaries & guidelines
│   └── verify_ml_environment.py                  # Read-only environment & model integrity checker
│
├── URL-ml/                                       # URL threat classification subsystem
│   ├── data/                                     # Raw/cleaned URL corpora (excluded from Git)
│   ├── docs/                                     # URL-ML architectural guide
│   ├── experiments/                              # Isolated stage gates & evaluation runs
│   ├── model/                                    # Challenger checkpoints & legacy models
│   ├── models/                                   # Production champion models (v8_champion.joblib, portable JSON)
│   ├── reports/                                  # Audit dossiers & gate reports
│   ├── scripts/                                  # 67-feature extractor, classifier, exporters
│   ├── tests/                                    # Automated pytest regression & parity suites
│   └── venv/                                     # Local virtual environment (excluded from Git)
│
├── Messages-ml/                                  # Message threat classification subsystem
│   ├── data/                                     # Raw/processed smishing corpora (excluded from Git)
│   ├── evaluation/                               # Evaluation scripts and logs
│   ├── messages_v4/                              # V4 model artifacts and experiments
│   ├── messages_v4_3/                            # V4.3 experimental runs
│   ├── messages_v4_4/                            # V4.4 experimental runs
│   ├── messages_v4_5/                            # V4.5 experimental runs
│   ├── messages_v5_sprint/                       # V5 dataset expansion sprint
│   ├── model/                                    # Candidate model checkpoints
│   ├── model_training/                           # Training audit scripts
│   ├── release/                                  # Release build artifacts & test APKs
│   ├── reports/                                  # Multi-class confusion & error analyses
│   ├── scripts/                                  # Dual TF-IDF vectorizers, tokenizers, runners
│   ├── tests/                                    # Automated message classification tests
│   ├── champion_model.pkl                        # Production champion V4 model
│   ├── champion_scaler.pkl                       # Feature scaler
│   ├── champion_tfidf.pkl                        # Word/char TF-IDF vectorizer
│   └── champion_v2_model.pkl                     # Production champion V2 / V4.5 model
│
├── android-runtime/                              # Pure Kotlin runtime bridge
│   ├── golden_test_data/                         # Cross-language golden test corpora (golden_urls_v8.json)
│   ├── url/assets/                               # Portable JSON bundles (v8_champion_portable.json)
│   ├── messages/assets/                          # Portable JSON message assets (champion_v2_*.json)
│   ├── tools/                                    # Kotlin evaluators, benchmarks, and generator tools
│   └── reports/                                  # Parity audit records
│
├── Databases/                                    # SQLite threat intelligence forensics (local only)
├── investigation/                                # Forensic DB analysis tools & row extractors
├── 7sep_messages_v3/                             # Baseline candidates & replay data
├── 6sep/                                         # Historical optimization manifests
├── archive/                                      # Historical model & dataset archives
├── New_history/                                  # Device replay message history logs
├── scratch/                                      # Experimental ablation studies and test jars
│
├── FINAL_ANDROID_DEPLOYMENT_READINESS.md         # Preserved root deployment readiness record
├── MESSAGES_V4_FINAL_REPORT.md                   # Preserved root Messages V4 report
├── MESSAGES_V4_FORENSIC_BASELINE.md              # Preserved root forensic baseline
├── MESSAGES_V4_RELEASE_DECISION.json             # Preserved root release decision ledger
└── V3_ARCHITECTURE_AUDIT.md                      # Preserved root V3 audit record
```

---

## 3. Files Moved or Copied

In strict accordance with the organizational rules:
- **Zero source code or model files were moved or deleted.**
- Existing root markdown files (`FINAL_ANDROID_DEPLOYMENT_READINESS.md`, `MESSAGES_V4_FINAL_REPORT.md`, etc.) were left in place because automation scripts (e.g. `android-runtime/tools/make_msg_kt.py:1758`) write directly to `Path('FINAL_ANDROID_DEPLOYMENT_READINESS.md')`.
- New files were added additively without overwriting or disrupting any existing scripts or relative paths:
  1. `sentinel-ml/.gitignore`
  2. `sentinel-ml/README.md`
  3. `sentinel-ml/GITHUB_PREPARATION_REPORT.md`
  4. `sentinel-ml/shared/contracts.py`
  5. `sentinel-ml/shared/README.md`
  6. `sentinel-ml/scripts/verify_ml_environment.py`
  7. `sentinel-ml/docs/ARCHITECTURE.md`
  8. `sentinel-ml/docs/MODEL_SPECIFICATIONS.md`
  9. `sentinel-ml/reports/README.md`

---

## 4. Nested Git Repositories Discovered

During recursive scanning of `sentinel-ml` (filtering for `.git*`), exactly **one** nested Git repository directory was located:

| Path | Mode | Item Count | Status |
| :--- | :--- | :--- | :--- |
| `sentinel-ml/URL-ml/.git` | `d-----` (Directory) | 0 items | Empty stub directory created during historical initialization. |

No other `.git` directories, `.git` files, Git submodules, or worktree pointers existed inside `sentinel-ml` or its subdirectories. (Only harmless `.pytest_cache/.gitignore` cache exclusion files were found in `.pytest_cache/` and `Messages-ml/.pytest_cache/`).

---

## 5. Git Metadata Backed Up and Removed

1. **Inspection**: The `sentinel-ml/URL-ml/.git` directory was inspected with PowerShell `Get-Item`. It was verified to be a standard empty directory (`Mode: d-----`, `Target: {}`, `LinkType: `) containing zero subfolders or files.
2. **Backup**: Copied recursively to a secure, permanent backup location outside `sentinel-ml`.
3. **Verification**: Confirmed backup existence and mode.
4. **Removal**: Removed `sentinel-ml/URL-ml/.git` using PowerShell `Remove-Item -Recurse -Force`.
5. **Confirmation**: Confirmed that `Test-Path "sentinel-ml/URL-ml/.git"` returned `False`.

---

## 6. Backup Locations & Verification Results

| Original Nested Metadata | Verified Backup Location | Verification Command Result |
| :--- | :--- | :--- |
| `sentinel-ml/URL-ml/.git` | `C:\Users\user\Programing files\Yajat\Projects\sentinel\backup_nested_git\URL-ml\.git` | `Test-Path` returned `True`; `Mode: d-----`; `Exists: True` |

The backup is located completely outside `sentinel-ml`, ensuring that `sentinel-ml` remains free of nested Git metadata when initialized.

---

## 7. `.gitignore` Rules

A tailored `.gitignore` was authored at `sentinel-ml/.gitignore` containing rules for:

1. **Python & Bytecode**: `__pycache__/`, `*.py[cod]`, `*$py.class`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage`.
2. **Virtual Environments**: `.venv/`, `venv/`, `env/`, `ENV/`.
3. **Credentials & Secrets**: `.env`, `.env.*`, `!.env.example`, `*.pem`, `*.key`, `*credentials*.json`, `*secrets*.json`.
4. **IDE & Tooling**: `.vscode/`, `.idea/`, `.kilo/`, `.agents/`, `*.sublime-*`.
5. **Operating System Artifacts**: `.DS_Store`, `Thumbs.db`, `desktop.ini`, `ehthumbs.db`.
6. **Temporary Files & Logs**: `*.tmp`, `*.temp`, `*.log`, `*.bak`, `*.swp`.
7. **Local Caches & Tracking**: `.cache/`, `cache/`, `wandb/`, `mlruns/`, `lightning_logs/`.
8. **Large Datasets & Databases**: `raw/`, `downloads/`, `external/`, `private/`, `secrets/`, `*.csv`, `*.tsv`, `*.npy`, `*.npz`, `*.xml`, `*.parquet`, `Databases/`, `*.db*`, `*.jsonl`.
9. **Binary Model Artifacts & Checkpoints**: `checkpoints/`, `*.pkl`, `*.pickle`, `*.joblib`, `*.onnx`, `*.tflite`, `*.h5`, `*.pt`, `*.pth`.
10. **Archives, Packages & Heavy Tools**: `*.zip`, `*.7z`, `*.tar.gz`, `*.apk`, `*.aab`, `*.jar`, `android-runtime/tools/kotlinc/`.

*Note: Portable JSON runtime models (`*_portable.json`, `champion_v2_*.json`) are text-based and remain trackable by Git.*

---

## 8. Model Files Needed for Competition Demonstration

Every trained model artifact has been **strictly preserved locally** on disk. No model was deleted or modified.

### 8.1 Required Artifacts Summary

| Subsystem | Model Artifact Path | Size | Role in Demonstration / Inference | Loading Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **URL-ML** | `URL-ml/models/v8_champion.joblib` | 693 KB | Python reference evaluation; baseline benchmark. | Loaded via `joblib.load()` into `HistGradientBoostingClassifier`. |
| **URL-ML** | `URL-ml/models/v8_champion_portable.json` | 1,005 KB | On-device production inference for Android; golden test parity. | Loaded via `HistGbmTreeEvaluator` (pure Kotlin, zero external dependencies). |
| **URL-ML** | `URL-ml/models/v8_parent_profiles.json` | 21.4 MB | Domain brand reputation and safe-gating profile dictionary. | Loaded via JSON parser in `v8_parent_profiler.py` and `SafeDomainAdjudicator`. |
| **Messages-ML** | `Messages-ml/champion_model.pkl` | 1.50 MB | Python reference Messages V4 classifier (3-class ExtraTrees). | Loaded via `pickle.load()` into scikit-learn pipeline. |
| **Messages-ML** | `Messages-ml/champion_tfidf.pkl` | 76.5 KB | Dual TF-IDF vectorizer (word 1-2 n-grams, char 3-5 n-grams). | Loaded via `pickle.load()`. |
| **Messages-ML** | `Messages-ml/champion_scaler.pkl` | 48.9 KB | Feature scaling normalization parameters. | Loaded via `pickle.load()`. |
| **Messages-ML** | `Messages-ml/champion_v2_model.pkl` | 1.74 MB | Messages V4.5 / Candidate single-stage model. | Loaded via `pickle.load()`. |
| **Messages-ML** | `android-runtime/messages/assets/champion_v2_trees.json` | 1.1 MB | Pure Kotlin decision tree traversal model on Android. | Loaded via `TreeEvaluator` from Android assets. |
| **Messages-ML** | `android-runtime/messages/assets/champion_v2_*_vocab_idf.json` | 60 KB | Vocabulary token mappings and IDF weights on Android. | Loaded via JSON asset loader. |

### 8.2 Loading After Cloning
- **Mobile Evaluation**: The portable JSON models are tracked by Git and load immediately in Android without downloading binary blobs.
- **Python Demonstration**: Downstream users who clone the repository can obtain the binary `.joblib` and `.pkl` models via GitHub Releases or Git LFS. Their SHA-256 hashes are documented in [`docs/MODEL_SPECIFICATIONS.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/docs/MODEL_SPECIFICATIONS.md).

---

## 9. Files Excluded from GitHub

The following file categories are deliberately excluded from Git via `.gitignore` to protect security, privacy, and repository performance:

| Category | Typical Files / Directories in `sentinel-ml` | Reason for Exclusion |
| :--- | :--- | :--- |
| **Virtual Environments** | `URL-ml/venv/` (contains 1 GB `_pywrap_tensorflow_common.dll`, 80 MB `libclang.dll`) | Exceeds GitHub 100 MB hard limit; machine-specific binaries. |
| **Raw / Bulky Datasets** | `URL-ml/data/data.csv` (54.2 MB), `SRC_NUS_SMS_CORPUS_2013` (41.7 MB), `*.jsonl` dumps | Exceeds recommended 50 MB threshold; raw corpora should be hosted externally. |
| **Forensic Databases** | `Databases/*.db`, `sentinel_db(1)`, `test_fixed.db` | Local SQLite databases contain historical threat forensics and large binary blobs. |
| **Binary Model Pickles** | `*.joblib`, `*.pkl` | Binary pickle serialization risk; large binary churn in Git history. |
| **Tool Distributions** | `android-runtime/tools/kotlinc/` (contains 58.8 MB `kotlin-compiler.jar`), `*.jar` | Heavy compiler binaries and precompiled test JARs. |
| **Android Packages & Zips** | `Messages-ml/release/apk/*.apk` (30.1 MB), `archive/history/*.zip` (25.1 MB) | Large binary distribution artifacts. |
| **Local Caches** | `.pytest_cache/`, `__pycache__/`, `URL-ml/.agents/` | Ephemeral build and test execution caches. |

---

## 10. Security Concerns

A thorough inspection of `sentinel-ml` was performed:
1. **Credentials & API Keys**:
   - Zero hardcoded API keys, tokens, `.env` files, or SSH/TLS private keys (`.pem`, `.key`) were identified in the source tree outside `certifi` CA certificates inside `venv/`.
   - References to words like "token" or "credential" in `Messages-ml/model_training/` relate strictly to SMS text threat token analysis (smishing classifiers detecting OTP/password solicitations).
2. **Pickle Deserialization Warning**:
   - Binary models (`champion_model.pkl`) utilize Python `pickle`. A security notice is documented in `MODEL_SPECIFICATIONS.md` advising users to verify SHA-256 digests and avoid unpickling untrusted files.
3. **URL Safety**:
   - URL threat corpora and test strings in `URL-ml/data` contain malicious URLs. All testing scripts handle them purely as passive strings without network domain resolution or HTTP requests.

---

## 11. Broken Paths & Unresolved Issues

- **Relative Paths Check**: Verified that no existing relative paths were broken. Scripts referencing `android-runtime` (`ROOT.parent / "android-runtime"`), `Databases/`, and `investigation/` find all target files at their expected locations.
- **Python Import Parity**: `sys.path` entries in `URL-ml/scripts/` and `Messages-ml/scripts/` remain fully functional.
- **Cross-Language Golden Corpus**: `android-runtime/golden_test_data/golden_urls_v8.json` remains present, and mathematical parity ($< 10^{-4}$) is preserved.
- **Unresolved Issues**: **None.**

---

## 12. Repository Readiness Verdict

### **VERDICT: READY FOR MANUAL GIT INITIALIZATION**

`sentinel-ml` is in a clean, self-contained state:
- Zero nested `.git` directories or files remain inside `sentinel-ml`.
- `sentinel-ai` is completely untouched (last modified September 7, 2026).
- `sentinel_datasets` was not accessed.
- All models, features, training scripts, and tests remain intact locally.
- `.gitignore` and `README.md` are in place.
- Verification utility `scripts/verify_ml_environment.py` passes all checks with exit code 0.

### Recommended User Next Steps (Manual Git Commands):

```bash
cd "c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml"

# 1. Initialize Git repository
git init

# 2. Stage non-ignored files
git add .

# 3. Verify staged files adhere to .gitignore (no large binaries or venvs staged)
git status

# 4. Create initial commit
git commit -m "feat(ml): initialize sentinel-ml independent repository"

# 5. Link GitHub remote and push
# git remote add origin https://github.com/<org>/sentinel-ml.git
# git branch -M main
# git push -u origin main
```

---

## 13. Final Root Directory Cleanup

Following the initial repository staging, a comprehensive audit and reorganization of all remaining items outside `sentinel-ai/` and `sentinel-ml/` was performed to complete the repository consolidation.

### 13.1 Comprehensive Inventory of Root Items (Outside `sentinel-ai` and `sentinel-ml`)

| Item Name | Type | Size | Purpose & Role | Belongs to ML? | Proposed Action & Destination | Dependency Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`docs/`** | Directory | 4.54 KB (1 file) | Contained `WORKSPACE_ARCHITECTURE.md` (cross-tier architecture & parity contracts). | **Yes** | Moved to [`sentinel-ml/docs/WORKSPACE_ARCHITECTURE.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/docs/WORKSPACE_ARCHITECTURE.md). Empty folder removed. | Safe. No code dependencies broken. |
| **`research/`** | Directory | 2.77 KB (1 file) | Contained `README.md` (threat classification taxonomies & governance). | **Yes** | Moved to [`sentinel-ml/docs/RESEARCH_NOTES.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/docs/RESEARCH_NOTES.md). Empty folder removed. | Safe. Pure documentation. |
| **`tools/`** | Directory | 0.81 KB (1 file) | Contained `README.md` (workspace tooling boundary rules). | **Yes** | Moved to [`sentinel-ml/scripts/README.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/scripts/README.md). Empty folder removed. | Safe. Integrates into ML scripts. |
| **`assistant_review_20261023/`** | Directory | 107.5 KB (5 files) | Independent analyst review dossiers for Agent A (Messages) & Agent C (URL). | **Yes** | Moved intact to [`sentinel-ml/reports/assistant_review_20261023/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/assistant_review_20261023/). | Safe. Zero internal or external imports. |
| **`reports/`** | Directory | ~323 MB (583 files) | ML sprint evaluation corpora (`url_sprint_01`, `dev_sprint_01`, `simulation_diagnosis`, `WORKSPACE_ORGANIZATION_REPORT.md`). | **Yes** | Moved complete subdirectories into [`sentinel-ml/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/). Empty folder removed. | Safe. Preserves all internal sprint structures. |
| **`backup_nested_git/`** | Directory | 0 bytes | Preserved backup of nested `.git` metadata from `sentinel-ml/URL-ml/.git`. | **No** (Meta) | **Preserved outside both repositories.** | Safe. Must not be uploaded. |
| **`.pytest_cache/`** | Directory | 4.64 KB (4 files) | Ephemeral root test execution cache from historical test runs. | **No** (Cache) | **Preserved outside.** `sentinel-ml` already has its own `.pytest_cache`. | Safe. Deletion avoided per zero-deletion rule. |
| **`README.md`** | File | 6.19 KB | Parent workspace navigation guide covering both `sentinel-ai` and `sentinel-ml`. | **Workspace-wide** | **Preserved outside** with documented reason; reference copy placed in `sentinel-ml/docs/WORKSPACE_ROOT_README.md`. | Safe. Serves root folder workspace navigation. |

---

### 13.2 Detailed Relocation Ledger

| Original Path | Destination Path in `sentinel-ml` | Type | Migration Result |
| :--- | :--- | :--- | :--- |
| `Sentinel/docs/WORKSPACE_ARCHITECTURE.md` | `sentinel-ml/docs/WORKSPACE_ARCHITECTURE.md` | File | Successfully moved; zero collisions. |
| `Sentinel/research/README.md` | `sentinel-ml/docs/RESEARCH_NOTES.md` | File | Successfully moved; zero collisions. |
| `Sentinel/tools/README.md` | `sentinel-ml/scripts/README.md` | File | Successfully moved; zero collisions. |
| `Sentinel/assistant_review_20261023/` | `sentinel-ml/reports/assistant_review_20261023/` | Directory | Successfully moved intact (all 5 files). |
| `Sentinel/reports/dev_sprint_01/` | `sentinel-ml/reports/dev_sprint_01/` | Directory | Successfully moved intact (`hinglish_probe`, `sprint_v2_20261023`). |
| `Sentinel/reports/url_sprint_01/` | `sentinel-ml/reports/url_sprint_01/` | Directory | Successfully moved intact (benchmarks, logs, gates, CSVs). |
| `Sentinel/reports/simulation_diagnosis/` | `sentinel-ml/reports/simulation_diagnosis/` | Directory | Successfully moved intact (preflight, runs, traces). |
| `Sentinel/reports/WORKSPACE_ORGANIZATION_REPORT.md` | `sentinel-ml/reports/WORKSPACE_ORGANIZATION_REPORT.md` | File | Successfully moved; zero collisions. |
| `Sentinel/README.md` | `sentinel-ml/docs/WORKSPACE_ROOT_README.md` | File | Reference copy created in docs; original kept for root navigation. |

*Note: All empty parent shells (`Sentinel/docs`, `Sentinel/research`, `Sentinel/tools`, `Sentinel/reports`) were cleaned up after their contents were safely transferred.*

---

### 13.3 Items Intentionally Left Outside `sentinel-ml`

Exactly three items remain in the parent `Sentinel/` root directory outside `sentinel-ai` and `sentinel-ml`, each with an explicit documented justification:

1. **`backup_nested_git/`**:
   - **Justification**: Contains the verified filesystem backup of nested Git repository metadata (`URL-ml/.git`). Per Section 4 & 5 of the mandate, this must **never** be placed inside `sentinel-ml` (to avoid reintroducing nested Git metadata into the ML repo) or `sentinel-ai`. It remains outside both repositories as a safety escrow.
2. **`.pytest_cache/`**:
   - **Justification**: Ephemeral test execution cache generated by root-level pytest runs. Moving it into `sentinel-ml` would cause an overwrite collision with `sentinel-ml/.pytest_cache/`. Deleting it was avoided to uphold the strict zero-deletion rule. It is ignored by `.gitignore` and harmlessly resides at the workspace root.
3. **`README.md`**:
   - **Justification**: This file is the high-level parent workspace guide for developers opening the top-level `Sentinel/` directory in an IDE. It explains the boundary between the Android mobile repo (`sentinel-ai/`) and the ML intelligence repo (`sentinel-ml/`). Because it serves the parent multi-repo container rather than only `sentinel-ml`, it properly resides at the root (and is mirrored inside `sentinel-ml/docs/WORKSPACE_ROOT_README.md`).

---

### 13.4 Dependency & Parity Verification

- **Code Execution Parity**: Ran `python scripts/verify_ml_environment.py` within `sentinel-ml/URL-ml/venv`. All checks passed (`RESULT: SUCCESS — sentinel-ml environment & artifacts are verified!`).
- **Cryptographic Model Verification**:
  - `URL-ml/models/v8_champion.joblib`: Verified SHA-256 (`073e70f2...`).
  - `URL-ml/models/v8_champion_portable.json`: Verified SHA-256 (`e0e5e817...`).
  - `Messages-ml/champion_model.pkl`: Verified present and unaltered.
- **Git Metadata Check**: Re-confirmed that **zero** nested `.git` directories or pointers exist inside `sentinel-ml/` or any of its subdirectories.
- **`sentinel-ai` Boundary**: Confirmed **100% untouched** (last modified: September 7, 2026).
- **Unresolved Dependency Concerns**: **None.**

---

### 13.5 Final Sentinel Workspace Root Directory Tree

```text
Sentinel/
├── .pytest_cache/                                # Preserved root test cache (documented justification)
├── backup_nested_git/                            # Preserved Git metadata backup (safely isolated)
│   └── URL-ml/
│       └── .git/                                 # Backed-up empty Git stub from URL-ml
│
├── sentinel-ai/                                  # [PROTECTED BOUNDARY] Production Android Git repository
│   └── .git/                                     # Independent Android Git repository root (untouched)
│
├── sentinel-ml/                                  # [TARGET REPOSITORY] Independent ML Git repository
│   ├── .gitignore                                # Comprehensive ML Git exclusion rules
│   ├── README.md                                 # Master Sentinel-ML repository documentation
│   ├── GITHUB_PREPARATION_REPORT.md              # Complete migration and readiness report
│   │
│   ├── URL-ml/                                   # URL threat classification subsystem
│   ├── Messages-ml/                              # Message / SMS threat classification subsystem
│   ├── android-runtime/                          # Pure-Kotlin portable ML runtime bridge & golden test corpora
│   │
│   ├── docs/                                     # Subsystem architectural documentation
│   │   ├── ARCHITECTURE.md                       # ML architecture & Risk Fusion Engine guide
│   │   ├── MODEL_SPECIFICATIONS.md               # Model catalog, schemas & distribution guide
│   │   ├── RESEARCH_NOTES.md                     # Consolidated threat classification taxonomies
│   │   ├── WORKSPACE_ARCHITECTURE.md             # Cross-tier architectural contracts & boundaries
│   │   └── WORKSPACE_ROOT_README.md              # Parent workspace overview copy
│   │
│   ├── reports/                                  # Central index & sprint evaluation dossiers
│   │   ├── README.md                             # Consolidated reports directory index
│   │   ├── WORKSPACE_ORGANIZATION_REPORT.md      # Prior workspace organization audit
│   │   ├── assistant_review_20261023/            # Independent AI analyst reviews & sample annotations
│   │   ├── dev_sprint_01/                        # Messages-ML Hinglish & sprint evaluation runs
│   │   ├── url_sprint_01/                        # URL-ML sprint evaluation benchmarks & gate audits
│   │   └── simulation_diagnosis/                 # ML threat simulation traces & preflight logs
│   │
│   ├── scripts/                                  # Repository utilities & verification tools
│   │   ├── README.md                             # Tooling boundary rules & execution guide
│   │   └── verify_ml_environment.py              # Read-only environment & model integrity checker
│   │
│   ├── shared/                                   # Shared data contracts & protocols
│   │   ├── contracts.py                          # Severity, class enums & dataclass contracts
│   │   └── README.md                             # Interface specifications
│   │
│   ├── Databases/                                # SQLite threat intelligence forensics (local only)
│   ├── investigation/                            # Forensic recovery scripts & database parsers
│   ├── 7sep_messages_v3/                         # Historical baseline candidates & replay data
│   ├── 6sep/                                     # Historical optimization manifests
│   ├── archive/                                  # Historical model & dataset archives
│   ├── New_history/                              # Device replay message history logs
│   ├── scratch/                                  # Experimental ablation studies and test jars
│   ├── FINAL_ANDROID_DEPLOYMENT_READINESS.md     # Preserved root deployment readiness record
│   ├── MESSAGES_V4_FINAL_REPORT.md               # Preserved root Messages V4 report
│   ├── MESSAGES_V4_FORENSIC_BASELINE.md          # Preserved root forensic baseline
│   ├── MESSAGES_V4_RELEASE_DECISION.json         # Preserved root release decision ledger
│   └── V3_ARCHITECTURE_AUDIT.md                  # Preserved root V3 audit record
│
└── README.md                                     # Master parent workspace entry point (documented justification)
```

---

### 13.6 Final GitHub Readiness Sign-Off

The root-level directory reorganization is **complete and verified**. All machine-learning documentation, evaluation sprints, diagnostic logs, and research taxonomies have been cleanly migrated into their designated homes inside `sentinel-ml/`.

`sentinel-ml` is now completely self-contained and ready for manual Git repository initialization (`git init`) and publishing to GitHub.

