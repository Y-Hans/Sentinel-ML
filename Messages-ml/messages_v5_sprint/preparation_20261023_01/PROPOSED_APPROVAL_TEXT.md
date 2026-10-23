# Proposed approval text — not an approval

## 1. Verification-only handoff, when B is ready

“I authorize Agent B, after its source audit is complete and Agent A is paused, to copy the immutable release identified by [B manifest SHA256] into a new non-existing sentinel-ml/datasets_v5/[release ID] folder. Do not overwrite anything. Agent B writes a completion receipt and source quarantine manifest. Agent A may then verify hashes, audit admissibility and create proposed grouped splits in its Messages folder. No training, threshold scan, sealed-exam content access, Android edit or export is authorized.”

The bracketed release identity is intentionally not invented; it must be filled with B's actual final hash/path at approval. After copy, send DATASETS MOVED with the receipt path.

## 2. Later Messages fit approval, only after verified inputs and splits

“I approve the parent registration plus PRE_REGISTRATION_AMENDMENT_v2 identified in PREPARATION_APPROVAL_BUNDLE.json, accepted data manifest [actual SHA256] and final split manifest [actual SHA256]. I authorize only the twoC1fresh CPU fits (seeds20261023/20261024) and validation-only threshold selection, within5threads and10CPU-hours, with the >90min first-fit projection stop. No new features, larger vocabulary, temperature, export, Kotlin/Gradle or promotion. I acknowledge any explicitly listedUNPROVEN source-heldout/hardneg gates; no deployment claim is authorized.”

Do not approve invented/unfilled hashes or treat this sample wording as consent. If prerequisite labels/holdouts remain contested, approve only further data preparation instead of fitting.

## 3. Independent Android authorization, optional later

“I authorize applying the exact proposed Android diff SHA256 from android_patch_preconditions.json after matching source hashes and running its12test groups plus existing regressions. Keep URL/fusion policies and model artifacts unchanged. This does not authorize training or promotion.”

No part of this document authorizes its own execution. Current task remains preparation-only.
