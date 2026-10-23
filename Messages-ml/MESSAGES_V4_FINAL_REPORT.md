# Messages V4 Final Report

## Release decision

**V4_NOT_PROMOTABLE**

This repository now contains a separately versioned, trained V4 candidate and Android-format export. It is deliberately **not** integrated into the app: protected security evaluations reject it. Replacing the frozen V2 runtime with a candidate that regresses electricity, Hinglish, and semantic social-engineering detection would be unsafe.

## Scope and preserved baseline

V2 remains untouched. Its four frozen artifact hashes continue to match the historical manifest. V2 used 70 deterministic features, 1,500 word TF-IDF features, 500 character TF-IDF features, a three-class HistGradientBoosting model, and a roughly 0.704 non-benign threshold. V3 tried contextual dampening and escalation around V2; its own reports show unsafe trust/context escape paths and weak Hinglish robustness.

## V4 data and representation

The V4 corpus is saved at `messages_v4/data/train_v4.jsonl`; its provenance and SHA-256 are in `messages_v4/dataset_manifest.json`. It starts from the existing `train_expanded_v5.jsonl` and adds 112 explicitly tagged controlled contrastive and Hinglish examples. Protected validation, test, OOD, benchmark, and V3 contextual test files were never copied into training or paraphrased into it.

Two immutable scratch experiments were trained with seed `20260914`:

| Candidate | Representation | Selection result |
|---|---|---|
| full_features | 70 deterministic + word/character TF-IDF | selected on validation |
| text_only | 70 hard-zeroed fields + word/character TF-IDF | rejected by validation selection |

Experiment 1 adds 112 controlled records. Experiment 2 (`messages_v4/experiment_2/`) adds a substantially larger compositional contrast set (same topic, but official-channel notice versus coercive disclosure request) and controlled Hinglish cases. Both experiments independently selected `full_features` on validation. Experiment 2 did not repair the decisive protected failures, so it is rejected rather than replacing experiment 1.

Both use a three-class `HistGradientBoostingClassifier` with 300 iterations. The threshold, 0.690, was selected on validation only by maximizing malicious recall subject to benign non-benign FPR no greater than 2%; test/OOD were read only afterward. Native tree probabilities were retained; no post-hoc calibration was fitted because the available validation split was already used for threshold selection.

## Compute

The host exposes an NVIDIA GeForce RTX 4060 with 8 GB VRAM, driver 610.62, and CUDA 13.3 driver support. The repository Python environment does not contain PyTorch, so no unverified neural dependency was introduced. Classical fitting used CPU; Windows sandbox worker-pipe restrictions required one OpenMP worker. The full-feature training run took 120.3 seconds.

## Results

| Evaluation | Benign non-benign FPR | Malicious recall |
|---|---:|---:|
| Validation | 1.98% | 87.52% |
| Test | 2.12% | 89.20% |
| OOD | 0.78% | 88.29% |
| Electricity protected slice | n/a | 33.33% |
| OTP-theft protected slice | n/a | 50.00% |
| Hinglish protected slice | 0.00% | 10.00% |
| Semantic counterfactual pairs | 0.00% | 17.50% |
| Saved-contact malicious | n/a | 67.50% |
| Group malicious | n/a | 67.50% |
| Institutional protected slice | 12.50% | 50.00% |
| Sentinel replay benign | 4.12% | 100.00% (3 cases) |

Experiment 2 produced TEST FPR/recall of 1.92%/89.01% and OOD FPR/recall of 0.39%/89.04%, but remained at 33.33% electricity recall, 10.00% Hinglish recall, and 17.50% semantic-pair recall. Its OTP recall was 75.00%, but a single improved slice does not overcome the remaining regressions.

Full matrices, the threshold frontier, all benchmark metrics, exact artifact hashes, and both candidate results are in `messages_v4/evaluation.json`. The protected results show exactly why aggregate random-split performance is insufficient: V4 is not an improvement in the required security/utility tradeoff.

## Export and Android status

The `messages_v4/android_assets/` directory contains portable word TF-IDF, character TF-IDF, scaler, tree, and manifest assets in the existing Android evaluator format. Python artifact files are in `messages_v4/artifacts/`. They have not been copied over V2 app assets, and Android parity/integration was not run because promotion was blocked before that authorized release step.

## Artifact hashes

The training-time hashes are in the `artifact_hashes` objects in the two evaluation files. The final corrected V4 manifest is `messages_v4/ARTIFACT_HASHES_CORRECTED.json`; the V4 artifacts are separate from all V2 paths.

## Limitation and next defensible work

The available non-protected data does not offer enough independently labeled Hinglish and cross-template social-engineering coverage to repair these regressions without training against protected examples or fabricating evidence. The next defensible iteration requires newly collected and independently labeled real messages, especially Hinglish, electricity/payment coercion, OTP theft, and conversational impersonation; keep those sources disjoint from final evaluation.
