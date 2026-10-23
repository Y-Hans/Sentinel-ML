# Reproduction Commands

Run from sentinel-ml/Messages-ml using the project Python environment.

## Frozen V4.3 reproduction

```powershell
python scripts\reproduce_frozen_v43.py
```

The script directly loads messages_v4_3/models/candidate_d/{model,scaler,word_vec,char_vec}.pkl and infers over data/processed/{val,test,ood}.jsonl. It does not train, tune tau, mutate protected data, or write into the frozen model directory. Outputs go to messages_v4_3/evaluation/reproduction_20260930/.

Expected headline results:

| Split | Malicious correct / total | Benign FP / total |
|---|---:|---:|
| VAL | 2222 / 2316 | 16 / 807 |
| TEST | 1510 / 1556 | 2 / 520 |
| OOD | 761 / 794 | 1 / 255 |

## Analysis-only counterfactual probe

```powershell
python scripts\probe_counterfactuals_v43.py
```

Evaluates ten manually authored text pairs without training and writes counterfactual_probes.json. These are mechanism probes, not independent evaluation evidence.

## Hash the frozen artifacts (PowerShell)

```powershell
Get-FileHash messages_v4_3\models\candidate_d\model.pkl,messages_v4_3\models\candidate_d\scaler.pkl,messages_v4_3\models\candidate_d\word_vec.pkl,messages_v4_3\models\candidate_d\char_vec.pkl -Algorithm SHA256
```

Expected values are listed in PROJECT_ML_DOSSIER.md. Do not run messages_v4_3/models/candidate_d_v4_3.py for reproduction: its training routine writes over candidate metrics and artifact pickles.
