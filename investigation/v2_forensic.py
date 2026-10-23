"""Empirical root-cause verification harness for Messages-ML Champion V2."""
import json, os, pickle, sys
import numpy as np

ML_ROOT = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml"
INV = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation"
sys.path.insert(0, os.path.join(ML_ROOT, "scripts"))

from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector

TAU = 0.704

def build_pipeline():
    clf = pickle.load(open(os.path.join(ML_ROOT, "champion_v2_model.pkl"), "rb"))
    tw = pickle.load(open(os.path.join(ML_ROOT, "champion_v2_tfidf_word.pkl"), "rb"))
    tc = pickle.load(open(os.path.join(ML_ROOT, "champion_v2_tfidf_char.pkl"), "rb"))
    sc = pickle.load(open(os.path.join(ML_ROOT, "champion_v2_scaler.pkl"), "rb"))
    cfg = FeatureConfig()
    return clf, tw, tc, sc, cfg

def vectorize(text, sender, tw, tc, sc, cfg):
    xd = np.array([extract_feature_vector(text, sender, cfg)], dtype=float)
    xw = tw.transform([text]).toarray()
    xc = tc.transform([text]).toarray()
    raw = np.hstack((xd, xw, xc))
    return sc.transform(raw)

def predict(text, sender, pipe):
    clf, tw, tc, sc, cfg = pipe
    X = vectorize(text, sender, tw, tc, sc, cfg)
    p = clf.predict_proba(X)[0]
    pnb = float(p[1] + p[2])
    return p, pnb

def label(p, pnb):
    if pnb < TAU:
        return "BENIGN"
    return "MALICIOUS" if p[2] >= p[1] else "SUSPICIOUS_SPAM"
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def main():
    pipe = build_pipeline()
    out = []

    def rec(text, sender, tag, note=""):
        p, pnb = predict(text, sender, pipe)
        out.append({
            "tag": tag, "note": note, "text": text, "sender": sender or "",
            "p_benign": float(p[0]), "p_susp": float(p[1]), "p_mal": float(p[2]),
            "p_nb": pnb, "label": label(p, pnb),
        })

    # 1. HP false positive
    hp = ("Hi everyone we have partnered with hp since many of you requested to get new laptops, "
          "you can directly procure from campus. We are soon announcing the partnership. Regards")
    rec(hp, None, "HP_ANNOUNCEMENT")
    for brand in ["Dell", "Microsoft", "Lenovo", "generic laptop company"]:
        rec(hp.replace("hp", brand), None, "HP_ANNOUNCEMENT_VARIANT", brand)

    # 2. institutional slice
    slice_path = os.path.join(ML_ROOT, "data", "benchmarks", "slice_institutional_partnerships.jsonl")
    legit_n = mal_n = 0
    legit_fp = mal_tp = 0
    with open(slice_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            p, pnb = predict(r["raw_text"], r.get("sender_header"), pipe)
            is_nb = pnb >= TAU
            if r["security_label"] == "BENIGN":
                legit_n += 1
                if is_nb:
                    legit_fp += 1
            else:
                mal_n += 1
                if is_nb:
                    mal_tp += 1
            out.append({
                "tag": "INSTITUTIONAL_" + r["security_label"],
                "note": r["message_id"], "text": r["raw_text"], "sender": r.get("sender_header", ""),
                "p_benign": float(p[0]), "p_susp": float(p[1]), "p_mal": float(p[2]),
                "p_nb": pnb, "label": label(p, pnb),
            })
    # 3. simulation cases (real device history, 294)
    sim_path = os.path.join(os.path.dirname(ML_ROOT), "6sep", "simulation", "SIMULATION_CASES.jsonl")
    sim = []
    with open(sim_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                sim.append(json.loads(line))
    sim_gt_mal = sum(1 for r in sim if str(r.get("ground_truth_class", "")).startswith("MALICIOUS"))
    sim_gt_benign = sum(1 for r in sim if str(r.get("ground_truth_class", "")).startswith("BENIGN"))
    sim_fp = 0
    sim_rec_fp = []
    for r in sim:
        p, pnb = predict(r.get("content", ""), None, pipe)
        is_nb = pnb >= TAU
        gt = str(r.get("ground_truth_class", ""))
        if gt.startswith("BENIGN") and is_nb:
            sim_fp += 1
            sim_rec_fp.append((r.get("id"), r.get("content"), pnb))
        out.append({
            "tag": "SIMULATION", "note": (r.get("id") or "") + "|" + (r.get("behavioral_outcome") or ""),
            "text": r.get("content", ""), "sender": r.get("sender", ""),
            "gt": gt,
            "p_benign": float(p[0]), "p_susp": float(p[1]), "p_mal": float(p[2]),
            "p_nb": pnb, "label": label(p, pnb),
        })

    # 4. legacy FP classes from 6sep reports
    legacy = [
        ("Ha ha..voh toh aap bhej do..because protype link hai..and images hai agar hum daale toh project ki..", "CLASS_A_HINGLISH"),
        ("\U0001f517 github.com | https://github.com/rsk97/Diabetic-Retinopathy-Detection", "CLASS_A_GH_LINK"),
        ("SENTINEL - SUNDAY\nSINOVA - SUNDAY", "CLASS_A_SENTINEL_SUNDAY"),
        ("Uploading: 789 kB of 789 kB (100%)", "CLASS_B_BACKUP"),
        ("Dear Customer,\nAmazon Prime is included in your Jio plan. Activate now to enjoy Prime Video Originals... Click the link to activate: https://www.jio.com/dl/my_sub", "CLASS_C_JIO_PROMO"),
        ("Your BESCOM electricity bill of Rs. 1420 is generated. Due date is 15 days from bill generation. Pay promptly.", "REPLAY_BESCOM"),
        ("Your order is out for delivery. Share delivery OTP with partner upon arrival", "REPLAY_DELIVERY_OTP"),
        ("Hello", "HELLO"),
    ]
    for txt, tag in legacy:
        rec(txt, None, tag)

    # Write detail
    with open(os.path.join(INV, "v2_forensic_detail.jsonl"), "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("classes:", list(pipe[0].classes_))
    print(f"HP message: p_nb={[o['p_nb'] for o in out if o['tag']=='HP_ANNOUNCEMENT'][0]:.4f}")
    print(f"Institutional slice: BENIGN FPR={legit_fp}/{legit_n} ({legit_fp/max(1,legit_n):.2%}), "
          f"MALICIOUS recall={mal_tp}/{mal_n} ({mal_tp/max(1,mal_n):.2%})")
    print(f"Simulation: benign={sim_gt_benign} malicious={sim_gt_mal}; model FP={sim_fp} "
          f"({sim_fp/max(1,sim_gt_benign):.2%} of benign)")
    for rid, txt, pnb in sorted(sim_rec_fp, key=lambda x: -x[2])[:10]:
        print(f"    FP p={pnb:.3f} {txt[:90]!r}")

main()