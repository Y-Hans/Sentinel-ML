import sys
from pathlib import Path
import json
import joblib
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml")
sys.path.insert(0, str(ROOT / "Messages-ml" / "scripts"))
sys.path.insert(0, str(ROOT / "6sep" / "messages" / "candidates"))

from feature_extraction_v3 import extract_feature_vector_v3, get_feature_names_v3
from feature_extraction import extract_message_features, get_feature_names

CANDS = ROOT / "6sep" / "messages" / "candidates"

for cand in ["v3a", "v3b"]:
    clf = joblib.load(CANDS / f"candidate_{cand}_model.pkl")
    scaler = joblib.load(CANDS / f"candidate_{cand}_scaler.pkl")
    tfidf_word = joblib.load(CANDS / f"candidate_{cand}_tfidf_word.pkl")
    tfidf_char = joblib.load(CANDS / f"candidate_{cand}_tfidf_char.pkl")

    class DualTfidf:
        def __init__(self, w, c):
            self.w = w
            self.c = c
        def transform(self, texts):
            w_mat = self.w.transform(texts).toarray()
            c_mat = self.c.transform(texts).toarray()
            return np.hstack((w_mat, c_mat))
    
    tfidf = DualTfidf(tfidf_word, tfidf_char)

    text = "Hi everyone we have partnered with hp since many of you requested to get new laptops, you can directly procure from campus. We are soon announcing the partnership. Regards"
    
    det_features = np.array([extract_feature_vector_v3(text, None, None)])
    tfidf_features = tfidf.transform([text])
    
    X_concat = np.hstack((det_features, tfidf_features))
    X_scaled = scaler.transform(X_concat)

    probs = clf.predict_proba(X_scaled)[0]
    print(f"\n{cand.upper()} Probabilities:")
    print(f"  BENIGN: {probs[0]:.4f}")
    print(f"  SUSPICIOUS: {probs[1]:.4f}")
    print(f"  MALICIOUS: {probs[2]:.4f}")
    print(f"  Non-benign: {probs[1]+probs[2]:.4f}")

    if cand == "v3b":
        print("\nWord TF-IDF Highest:")
        w_idx = np.argsort(tfidf_features[0, :1500])[::-1][:5]
        w_vocab_inv = {v: k for k, v in tfidf_word.vocabulary_.items()}
        for i in w_idx:
            if tfidf_features[0, i] > 0:
                print(f"  '{w_vocab_inv[i]}': {tfidf_features[0, i]:.4f}")

        print("\nChar TF-IDF Highest:")
        c_idx = np.argsort(tfidf_features[0, 1500:])[::-1][:5]
        c_vocab_inv = {v: k for k, v in tfidf_char.vocabulary_.items()}
        for i in c_idx:
            if tfidf_features[0, 1500+i] > 0:
                print(f"  '{c_vocab_inv[i]}': {tfidf_features[0, 1500+i]:.4f}")
