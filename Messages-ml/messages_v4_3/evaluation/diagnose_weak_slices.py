"""
Comprehensive diagnosis of every false negative and false positive on weak slices.
"""
import pickle
import json
import sys
from pathlib import Path
import numpy as np

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
REV_LABELS = {0: "BENIGN", 1: "SUSPICIOUS_SPAM", 2: "MALICIOUS"}

with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f:
    clf = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f:
    sc = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f:
    tw = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f:
    tc = pickle.load(f)

def predict_single(text: str, threshold: float = 0.61):
    st = extract_structural_signals(text)
    w = tw.transform([text]).toarray()
    c = tc.transform([text]).toarray()
    X = np.hstack([[st], w, c]).astype(np.float32)
    Xs = sc.transform(X)
    probs = clf.predict_proba(Xs)[0]
    p_nonbenign = float(probs[1] + probs[2])
    pred_class = 2 if (p_nonbenign >= threshold and probs[2] >= probs[1]) else (1 if p_nonbenign >= threshold else 0)
    return {
        "pred_class": pred_class,
        "pred_label": REV_LABELS[pred_class],
        "probs": probs,
        "p_nonbenign": p_nonbenign,
        "st": st,
        "top_words": [(list(tw.vocabulary_.keys())[list(tw.vocabulary_.values()).index(i)], w[0, i]) for i in np.where(w[0] > 0)[0]],
    }

def inspect_slice(suite_name: str, path: Path):
    if not path.exists():
        print(f"Skipping {suite_name}: path not found {path}")
        return
    rows = [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]
    
    print("\n" + "="*90)
    print(f"SLICE DIAGNOSIS: {suite_name} (Total Records: {len(rows)})")
    print("="*90)

    fn_count = 0
    fp_count = 0
    for idx, r in enumerate(rows):
        txt = r.get("raw_text", "")
        true_label = r.get("security_label", "BENIGN")
        true_class = LABELS.get(true_label, 0)
        res = predict_single(txt, threshold=0.61)

        is_fn = (true_class == 2 and res["pred_class"] != 2)
        is_fp = (true_class == 0 and res["pred_class"] != 0)

        if is_fn:
            fn_count += 1
            print(f"\n[FALSE NEGATIVE #{fn_count}] Record #{idx} (Expected: {true_label}, Got: {res['pred_label']})")
            print(f"  Text: \"{txt}\"")
            print(f"  Probs: Benign={res['probs'][0]:.4f}, Spam={res['probs'][1]:.4f}, Malicious={res['probs'][2]:.4f} (p_nonbenign={res['p_nonbenign']:.4f}, tau=0.61)")
            print(f"  Top Active Words: {[w for w, _ in res['top_words']]}")
            print(f"  Structural: Length={res['st'][0]:.0f}, Words={res['st'][1]:.0f}, has_url={res['st'][10]:.0f}, has_phone={res['st'][12]:.0f}, naked_url={res['st'][15]:.0f}, susp_naked={res['st'][18]:.0f}")

        elif is_fp:
            fp_count += 1
            print(f"\n[FALSE POSITIVE #{fp_count}] Record #{idx} (Expected: {true_label}, Got: {res['pred_label']})")
            print(f"  Text: \"{txt}\"")
            print(f"  Probs: Benign={res['probs'][0]:.4f}, Spam={res['probs'][1]:.4f}, Malicious={res['probs'][2]:.4f} (p_nonbenign={res['p_nonbenign']:.4f}, tau=0.61)")
            print(f"  Top Active Words: {[w for w, _ in res['top_words']]}")

    print(f"\nSummary for {suite_name}: {fn_count} False Negatives, {fp_count} False Positives")

def main():
    bench_dir = ROOT.parent / "7sep_messages_v3/data"
    slices_dir = ROOT / "data/benchmarks"

    # 1. Hinglish Robustness
    inspect_slice("bench_hinglish_robustness", bench_dir / "bench_hinglish_robustness.jsonl")

    # 2. Adversarial Semantic Pairs
    inspect_slice("bench_adversarial_semantic_pairs", bench_dir / "bench_adversarial_semantic_pairs.jsonl")

    # 3. Institutional Partnerships
    inspect_slice("slice_institutional_partnerships", slices_dir / "slice_institutional_partnerships.jsonl")

    # 4. Electricity Scam
    inspect_slice("slice_electricity_scam", slices_dir / "slice_electricity_scam.jsonl")

    # 5. OTP Theft
    inspect_slice("slice_otp_theft", slices_dir / "slice_otp_theft.jsonl")

    # 6. Trusted Sender Malicious
    inspect_slice("bench_trusted_sender_malicious", bench_dir / "bench_trusted_sender_malicious.jsonl")

    # 7. Group Context Malicious
    inspect_slice("bench_group_context_malicious", bench_dir / "bench_group_context_malicious.jsonl")

    # 8. Sentinel Replay
    inspect_slice("bench_sentinel_replay", bench_dir / "bench_sentinel_replay.jsonl")

if __name__ == "__main__":
    main()
