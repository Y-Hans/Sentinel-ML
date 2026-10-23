import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
EXP_DIR = ROOT / "messages_v4_5/experiments/next_architecture"

p = EXP_DIR / "controlled_validation_results.json"
data = json.load(open(p, "r", encoding="utf-8"))
paired = data["paired_records"]

missed = [r for r in paired if r["ground_truth"] == "MALICIOUS" and r["final_prediction"] != "MALICIOUS"]
print(f"Total missed threats (Category D): {len(missed)}")
for m in missed:
    print(f"\n[{m['message_id']}] Cat {m['category']} ({m['source_family']})")
    print(f"  Text: \"{m['text']}\"")
    print(f"  V4.3: P(B)={m['v43_p_benign']:.4f}, P(S)={m['v43_p_spam']:.4f}, P(M)={m['v43_p_malicious']:.4f}, Pred={m['v43_prediction']}")
    print(f"  Aux:  P(B)={m['aux_p_benign']:.4f}, P(S)={m['aux_p_spam']:.4f}, P(M)={m['aux_p_malicious']:.4f}, Margin={m['aux_margin']:.4f}")

# Also inspect the 36 benign false positives
ben_fp = [r for r in paired if r["ground_truth"] == "BENIGN" and r["final_prediction"] != "BENIGN"]
print(f"\n" + "="*80)
print(f"Total Benign False Positives: {len(ben_fp)}")
cat_fps = {}
for b in ben_fp:
    cat = b["category"]
    cat_fps[cat] = cat_fps.get(cat, 0) + 1
print("Benign FP breakdown by Category:", cat_fps)

for b in ben_fp[:10]:
    print(f"\n[{b['message_id']}] Cat {b['category']} ({b['source_family']})")
    print(f"  Text: \"{b['text']}\"")
    print(f"  V4.3: P(B)={b['v43_p_benign']:.4f}, P(S)={b['v43_p_spam']:.4f}, P(M)={b['v43_p_malicious']:.4f}, Pred={b['v43_prediction']}")
    print(f"  Aux:  P(B)={b['aux_p_benign']:.4f}, P(S)={b['aux_p_spam']:.4f}, P(M)={b['aux_p_malicious']:.4f}, Margin={b['aux_margin']:.4f}")
