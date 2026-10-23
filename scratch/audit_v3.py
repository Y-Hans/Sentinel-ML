import sys
from pathlib import Path
import json
import joblib
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml")
sys.path.insert(0, str(ROOT / "Messages-ml" / "scripts"))
sys.path.insert(0, str(ROOT / "6sep" / "messages" / "candidates"))

from feature_extraction import extract_message_features, get_feature_names

MODELS = ROOT / "Messages-ml" 

clf = joblib.load(MODELS / "champion_v2_model.pkl")
scaler = joblib.load(MODELS / "champion_v2_scaler.pkl")
tfidf_word = joblib.load(MODELS / "champion_v2_tfidf_word.pkl")
tfidf_char = joblib.load(MODELS / "champion_v2_tfidf_char.pkl")

class DualTfidf:
    def __init__(self, w, c):
        self.w = w
        self.c = c
    def transform(self, texts):
        w_mat = self.w.transform(texts).toarray()
        c_mat = self.c.transform(texts).toarray()
        return np.hstack((w_mat, c_mat))
    
tfidf = DualTfidf(tfidf_word, tfidf_char)

text = """Hi everyone we have partnered with hp since many of you requested to get new laptops, you can directly procure from campus.
We are soon announcing the partnership.
Regards"""

cfg = None
det_dict = extract_message_features(text, None, cfg)
det_names = get_feature_names(cfg)
det_features = np.array([[det_dict[k] for k in det_names]])

print("\nDeterministic Features (>0):")
for k, v in det_dict.items():
    if v > 0:
        print(f"  {k}: {v}")

tfidf_features = tfidf.transform([text])
X_concat = np.hstack((det_features, tfidf_features))
X_scaled = scaler.transform(X_concat)

probs = clf.predict_proba(X_scaled)[0]
print(f"\nV2 Probabilities:")
print(f"  BENIGN: {probs[0]:.4f}")
print(f"  SUSPICIOUS: {probs[1]:.4f}")
print(f"  MALICIOUS: {probs[2]:.4f}")
non_benign = probs[1]+probs[2]
print(f"  Non-benign: {non_benign:.4f}")

# Find out what produces 93?
# The prompt says: "The current Messages V3 system produced: Risk score: 93 / 100"
# Could it be Risk score = 93 because non_benign is 0.93?
