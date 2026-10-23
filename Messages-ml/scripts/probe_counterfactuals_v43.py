"""Analysis-only controlled text perturbations for frozen V4.3.

These hand-authored probes are diagnostic and are not independent evaluation data.
No model training or protected dataset edits occur.
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "messages_v4_3" / "models"))
from candidate_d_v4_3 import extract_structural_signals  # noqa: E402

ART = ROOT / "messages_v4_3" / "models" / "candidate_d"
OUT = ROOT / "messages_v4_3" / "evaluation" / "reproduction_20260930" / "counterfactual_probes.json"
TAU = 0.61
PROBES = [
    ("otp_polarity", "Your account was accessed. Do not share your OTP.", "Your account was accessed. Share your OTP."),
    ("otp_negation_scope", "Never share your OTP with anyone. Contact support in the official app.", "Share your OTP with anyone. Contact support in the official app."),
    ("greeting_punctuation", "Hello", "Hello."),
    ("greeting_lexeme", "Hello", "Hi"),
    ("utility_provider", "Your BESCOM electricity bill is ready. Pay through the official app when convenient.", "Your MSEDCL electricity bill is ready. Pay through the official app when convenient."),
    ("institution_swap", "Google Workspace access expires today. Sign in at http://campus-help.example to keep your account.", "Microsoft access expires today. Sign in at http://campus-help.example to keep your account."),
    ("url_presence", "Your account needs review. Visit the official app for details.", "Your account needs review. Visit http://account-review.example for details."),
    ("phone_presence", "Your electricity connection will be disconnected tonight. Contact support through the official app.", "Your electricity connection will be disconnected tonight. Call 9876543210."),
    ("apk_suffix", "Install the partner rewards app to claim your offer.", "Install the partner rewards app at rewards.apk to claim your offer."),
    ("punctuation_urgency", "Your account will be suspended today. Verify details at http://secure-check.example", "Your account will be suspended today!!! Verify details at http://secure-check.example"),
]


def infer(texts, model, scaler, word, char):
    structural = np.asarray([extract_structural_signals(x) for x in texts], dtype=np.float32)
    matrix = np.hstack([structural, word.transform(texts).toarray(), char.transform(texts).toarray()]).astype(np.float32)
    probs = model.predict_proba(scaler.transform(matrix))
    result = []
    for text, st, p in zip(texts, structural, probs):
        pnb = float(p[1] + p[2])
        label = "BENIGN" if pnb < TAU else ("MALICIOUS" if p[2] >= p[1] else "SUSPICIOUS_SPAM")
        result.append({"text": text, "label": label, "p_benign": float(p[0]), "p_spam": float(p[1]),
                       "p_malicious": float(p[2]), "p_nonbenign": pnb,
                       "structural": [float(v) for v in st], "url_present": bool(st[10]), "phone_present": bool(st[12])})
    return result


def main():
    with open(ART / "model.pkl", "rb") as f: model = pickle.load(f)
    with open(ART / "scaler.pkl", "rb") as f: scaler = pickle.load(f)
    with open(ART / "word_vec.pkl", "rb") as f: word = pickle.load(f)
    with open(ART / "char_vec.pkl", "rb") as f: char = pickle.load(f)
    out = []
    for family, left, right in PROBES:
        a, b = infer([left, right], model, scaler, word, char)
        out.append({"family": family, "left": a, "right": b,
                    "delta_p_nonbenign_right_minus_left": b["p_nonbenign"] - a["p_nonbenign"]})
    OUT.write_text(json.dumps({"warning": "Hand-authored diagnostic probes; not independent evaluation data.",
                               "threshold": TAU, "probes": out}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(OUT)
    for row in out:
        print(row["family"], row["left"]["label"], round(row["left"]["p_nonbenign"], 4), "=>",
              row["right"]["label"], round(row["right"]["p_nonbenign"], 4),
              "delta", round(row["delta_p_nonbenign_right_minus_left"], 4))


if __name__ == "__main__":
    main()
