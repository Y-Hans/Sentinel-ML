import json
from collections import Counter
from pathlib import Path

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")

with open(ROOT / "messages_v4_5/reports/v4_5_forensic_records.json", "r", encoding="utf-8") as f:
    data = json.load(f)

missed = data["malicious_missed_by_v45"]
recovered = data["malicious_recovered_by_v45"]
introduced_fp = data["benign_fp_introduced_by_v45"]
corrected_fp = data["benign_fp_corrected_by_v45"]

print("=" * 80)
print(f"TOTAL MALICIOUS TEST MISSED BY V4.5: {len(missed)}")
print(f"TOTAL MALICIOUS TEST RECOVERED BY V4.5: {len(recovered)}")
print(f"NET PRIMARY MALICIOUS REGRESSION: -{len(missed) - len(recovered)}")
print(f"TOTAL BENIGN FPs INTRODUCED BY V4.5: {len(introduced_fp)}")
print(f"TOTAL BENIGN FPs CORRECTED BY V4.5: {len(corrected_fp)}")
print("=" * 80)

mechs = Counter([m.get("failure_mechanism") for m in missed])
print("\nFailure Mechanism Breakdown for Missed Malicious:")
for k, v in mechs.items():
    print(f"  - {k}: {v} ({v/len(missed)*100:.1f}%)")

signals_missed = Counter()
for m in missed:
    for sig, val in m["signals"].items():
        if val:
            signals_missed[sig] += 1

print("\nSignals present in Missed Malicious records:")
for sig, cnt in signals_missed.most_common():
    print(f"  - {sig}: {cnt} ({cnt/len(missed)*100:.1f}%)")

print("\nSample Missed Examples (MALICIOUS -> BENIGN, count=" + str(mechs.get("MALICIOUS -> BENIGN", 0)) + "):")
for m in [x for x in missed if x.get("failure_mechanism") == "MALICIOUS -> BENIGN"][:5]:
    p = m["v45_probs"]
    vp = m["v43_probs"]
    print(f"  ID: {m['message_id']}")
    print(f"  V4.5: P(B)={p[0]:.3f}, P(S)={p[1]:.3f}, P(M)={p[2]:.3f} | Pred: {m['v45_pred']}")
    print(f"  V4.3: P(B)={vp[0]:.3f}, P(S)={vp[1]:.3f}, P(M)={vp[2]:.3f} | Pred: {m['v43_pred']}")
    print(f"  Text: {m['text'][:100]}")
    print()

print("\nSample Missed Examples (MALICIOUS -> SPAM, count=" + str(mechs.get("MALICIOUS -> SPAM", 0)) + "):")
for m in [x for x in missed if x.get("failure_mechanism") == "MALICIOUS -> SPAM"][:5]:
    p = m["v45_probs"]
    vp = m["v43_probs"]
    print(f"  ID: {m['message_id']}")
    print(f"  V4.5: P(B)={p[0]:.3f}, P(S)={p[1]:.3f}, P(M)={p[2]:.3f} | Pred: {m['v45_pred']}")
    print(f"  V4.3: P(B)={vp[0]:.3f}, P(S)={vp[1]:.3f}, P(M)={vp[2]:.3f} | Pred: {m['v43_pred']}")
    print(f"  Text: {m['text'][:100]}")
    print()

print("\nSample Introduced Benign False Positives (count=" + str(len(introduced_fp)) + "):")
for m in introduced_fp[:5]:
    p = m["v45_probs"]
    vp = m["v43_probs"]
    print(f"  ID: {m['message_id']}")
    print(f"  V4.5: P(B)={p[0]:.3f}, P(S)={p[1]:.3f}, P(M)={p[2]:.3f} | Pred: {m['v45_pred']}")
    print(f"  V4.3: P(B)={vp[0]:.3f}, P(S)={vp[1]:.3f}, P(M)={vp[2]:.3f} | Pred: {m['v43_pred']}")
    print(f"  Text: {m['text'][:100]}")
    print()
