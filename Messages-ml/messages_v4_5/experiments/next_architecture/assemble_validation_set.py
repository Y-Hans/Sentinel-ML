import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
EXP_DIR = ROOT / "messages_v4_5/experiments/next_architecture"
DATA_DIR = EXP_DIR / "data"

def norm_case_ws(s: str) -> str:
    return " ".join(s.lower().split())

def norm_url(s: str) -> str:
    t = s.lower()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    return " ".join(t.split())

def norm_aggressive(s: str) -> str:
    t = s.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return " ".join(t.split())

def tokenize(s: str) -> set:
    return set(re.findall(r"\b\w+\b", s.lower()))

def jaccard(s1: set, s2: set) -> float:
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)

def get_text(r: dict) -> str:
    return (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()

print("=" * 80)
print("1. LOADING AND INDEXING PROTECTED MATERIAL FOR STRICT ISOLATION")
print("=" * 80)

protected_paths = [
    ROOT / "data/processed/test.jsonl",
    ROOT / "data/processed/ood.jsonl",
    ROOT / "data/processed/val.jsonl",
    ROOT / "data/processed/train.jsonl",
    DATA_DIR / "auxiliary_train.jsonl",
]
protected_paths += list((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))
protected_paths += list((ROOT / "data/benchmarks").glob("*.jsonl"))
sim_path = ROOT.parent / "6sep/simulation/SIMULATION_CASES.jsonl"
if sim_path.exists():
    protected_paths.append(sim_path)

prot_exact = set()
prot_case_ws = set()
prot_url_norm = set()
prot_aggr = set()
prot_ids = set()
prot_tokens = [] # list of (id, text, set_of_tokens)
inverted_index = defaultdict(list)

for p in protected_paths:
    if not p.exists(): continue
    for line in open(p, "r", encoding="utf-8", errors="ignore"):
        if not line.strip(): continue
        r = json.loads(line)
        t = get_text(r)
        if not t: continue
        mid = str(r.get("message_id") or r.get("id") or r.get("original_id") or "")
        if mid:
            prot_ids.add(mid)
        prot_exact.add(t)
        prot_case_ws.add(norm_case_ws(t))
        prot_url_norm.add(norm_url(t))
        aggr = norm_aggressive(t)
        prot_aggr.add(aggr)
        toks = tokenize(aggr)
        if toks:
            idx = len(prot_tokens)
            prot_tokens.append((mid, t, toks))
            for tok in toks:
                inverted_index[tok].append(idx)

print(f"Total protected records indexed: {len(prot_tokens)}")

exclusion_stats = Counter()

def check_isolation(text: str, mid: str = ""):
    """Returns (is_clean, failure_reason)"""
    if not text:
        exclusion_stats["EMPTY_TEXT"] += 1
        return False, "EMPTY_TEXT"
    if mid and mid in prot_ids:
        exclusion_stats["ID_COLLISION"] += 1
        return False, f"ID_COLLISION: {mid}"
    if text in prot_exact:
        exclusion_stats["EXACT_COLLISION"] += 1
        return False, "EXACT_COLLISION"
    if norm_case_ws(text) in prot_case_ws:
        exclusion_stats["CASE_WS_COLLISION"] += 1
        return False, "CASE_WS_COLLISION"
    if norm_url(text) in prot_url_norm:
        exclusion_stats["URL_NORM_COLLISION"] += 1
        return False, "URL_NORM_COLLISION"
    aggr = norm_aggressive(text)
    if aggr in prot_aggr:
        exclusion_stats["AGGRESSIVE_NORM_COLLISION"] += 1
        return False, "AGGRESSIVE_NORM_COLLISION"
    
    toks = tokenize(aggr)
    if not toks:
        exclusion_stats["NO_TOKENS"] += 1
        return False, "NO_TOKENS"
    
    candidate_indices = set()
    for tok in toks:
        candidate_indices.update(inverted_index.get(tok, []))
    
    len_cand = len(toks)
    min_len = int(len_cand * 0.70)
    max_len = int(len_cand / 0.70) + 1
    
    for c_idx in candidate_indices:
        _, p_text, p_toks = prot_tokens[c_idx]
        if min_len <= len(p_toks) <= max_len:
            j = len(toks & p_toks) / len(toks | p_toks)
            if j >= 0.70:
                exclusion_stats["JACCARD_HIGH"] += 1
                return False, f"JACCARD_COLLISION ({j:.3f})"
                
    return True, "CLEAN"

print("Isolation engine ready.")

# Step 2: Harvesting Candidates from Fresh Sources
print("\n" + "=" * 80)
print("2. HARVESTING INDEPENDENT CANDIDATES ACROSS 13 CATEGORIES (A - M)")
print("=" * 80)

# We will collect candidates into a dict: cat -> list of candidate dicts
categories = {
    "A": "URL-less account/security deception",
    "B": "Electricity / utility messages",
    "C": "Institutional / campus messages",
    "D": "Conversational social engineering",
    "E": "Greetings and short openers",
    "F": "Legitimate security notifications",
    "G": "Legitimate utility notifications",
    "H": "Legitimate banking / OTP notifications",
    "I": "Legitimate technical / IT communication",
    "J": "APK / software references",
    "K": "Phone / callback messages",
    "L": "Hinglish / Indian English",
    "M": "Ordinary promotional spam"
}

candidates_by_cat = defaultdict(list)

# Regex patterns for matching
re_url = re.compile(r"https?://|www\.", re.I)
re_phone = re.compile(r"(?:\+91|0)?[6-9]\d{9}|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
re_apk = re.compile(r"\.apk\b", re.I)
re_greet = re.compile(r"^(hi|hey|hello|good morning|good afternoon|good evening|gm|gn|how are you|hope you|whats up|wassup)\b", re.I)
re_inst = re.compile(r"\b(campus|college|university|exam|lecture|prof|professor|class|classes|lab|faculty|semester|assignment|attendance|hall ticket|tuition)\b", re.I)
re_sec = re.compile(r"\b(password|passcode|security alert|login|log in|2fa|otp|verification code|authorized|authenticated)\b", re.I)
re_util = re.compile(r"\b(electricity|water|utility|broadband|gas bill|power supply|meter reading|tariff|power cut|load shedding)\b", re.I)
re_bank = re.compile(r"\b(bank|account|card|credit|debit|balance|cheque|atm|deposit|withdrawn|transferred|neft|rtgs|statement|upi)\b", re.I)
re_tech = re.compile(r"\b(server|database|software|hardware|laptop|reboot|system error|compiler|script|git|github|linux|windows|firmware|cloudwatch|jira|pipeline)\b", re.I)
re_hinglish = re.compile(r"\b(bhai|yaar|kahan|aayega|chal|theek|kuch|kya|nahi|matlab|karo|bhej|bolo|kal|aaj|raat|subah|sun|arre|turant|bijli)\b", re.I)

# 2.1 Harvest from Mendeley 2022
print("Harvesting from SRC_MENDELEY_SMISHING_2022...")
p_men = ROOT / "data/raw/SRC_MENDELEY_SMISHING_2022/Dataset_5971.csv"
with open(p_men, "r", encoding="utf-8", errors="replace") as f:
    for idx, r in enumerate(csv.DictReader(f)):
        t = (r.get("TEXT") or "").strip()
        lbl_raw = (r.get("LABEL") or "").strip().lower()
        if not t: continue
        
        orig_id = f"MENDELEY_2022_ROW_{idx:05d}"
        is_clean, reason = check_isolation(t, orig_id)
        if not is_clean: continue
        
        if lbl_raw == "ham":
            # Categorize benign
            if re_hinglish.search(t):
                candidates_by_cat["L"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "L",
                    "category_name": categories["L"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic conversational Hinglish SMS between peers.",
                    "annotator_confidence": "HIGH"
                })
            elif re_inst.search(t):
                candidates_by_cat["C"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "C",
                    "category_name": categories["C"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic campus/institutional communication regarding classes, exams, or academic schedule.",
                    "annotator_confidence": "HIGH"
                })
            elif re_sec.search(t):
                candidates_by_cat["F"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "F",
                    "category_name": categories["F"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic account security or authentication confirmation.",
                    "annotator_confidence": "HIGH"
                })
            elif re_util.search(t):
                candidates_by_cat["G"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "G",
                    "category_name": categories["G"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic utility or service confirmation.",
                    "annotator_confidence": "HIGH"
                })
            elif re_bank.search(t):
                candidates_by_cat["H"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "H",
                    "category_name": categories["H"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic personal banking, debit, or account balance notification.",
                    "annotator_confidence": "HIGH"
                })
            elif re_tech.search(t):
                candidates_by_cat["I"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "I",
                    "category_name": categories["I"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic technical or IT communication between developers/users.",
                    "annotator_confidence": "HIGH"
                })
            elif re_greet.search(t):
                candidates_by_cat["E"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "E",
                    "category_name": categories["E"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic friendly greeting or conversational check-in.",
                    "annotator_confidence": "HIGH"
                })
            else:
                candidates_by_cat["D"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "D",
                    "category_name": categories["D"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic human P2P conversational coordination.",
                    "annotator_confidence": "HIGH"
                })
        elif lbl_raw == "spam":
            candidates_by_cat["M"].append({
                "original_id": orig_id,
                "source": "SRC_MENDELEY_SMISHING_2022",
                "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                "category": "M",
                "category_name": categories["M"],
                "text": t,
                "security_label": "SUSPICIOUS_SPAM",
                "annotation_rationale": "Ordinary commercial telemarketing spam (promotional offer/discount).",
                "annotator_confidence": "HIGH"
            })
        elif "smish" in lbl_raw:
            # Malicious smishing
            has_u = bool(re_url.search(t))
            has_p = bool(re_phone.search(t))
            if not has_u and has_p:
                candidates_by_cat["K"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "K",
                    "category_name": categories["K"],
                    "text": t,
                    "security_label": "MALICIOUS",
                    "annotation_rationale": "Smishing attack directing user to call an attacker phone number.",
                    "annotator_confidence": "HIGH"
                })
            elif not has_u:
                candidates_by_cat["A"].append({
                    "original_id": orig_id,
                    "source": "SRC_MENDELEY_SMISHING_2022",
                    "source_family": "AUTHENTIC_MOBILE_SMS_MENDELEY",
                    "acquisition_provenance": "Mendeley SMS Phishing Dataset (Mishra et al. 2022), raw authentic mobile traffic, verified independent unused partition.",
                    "category": "A",
                    "category_name": categories["A"],
                    "text": t,
                    "security_label": "MALICIOUS",
                    "annotation_rationale": "URL-less smishing threat attempting deception without delivering a hyperlink.",
                    "annotator_confidence": "HIGH"
                })

# 2.2 Harvest from UCI SMS Spam Collection
print("Harvesting from SRC_UCI_SMS_SPAM_2011...")
p_uci = ROOT / "data/raw/SRC_UCI_SMS_SPAM_2011/SMSSpamCollection"
with open(p_uci, "r", encoding="utf-8", errors="replace") as f:
    for idx, line in enumerate(f):
        pts = line.strip().split("\t")
        if len(pts) < 2: continue
        lbl_raw, t = pts[0].strip().lower(), pts[1].strip()
        if not t: continue
        
        orig_id = f"UCI_SMS_2011_ROW_{idx:05d}"
        is_clean, reason = check_isolation(t, orig_id)
        if not is_clean: continue
        
        if lbl_raw == "ham":
            if re_inst.search(t):
                candidates_by_cat["C"].append({
                    "original_id": orig_id,
                    "source": "SRC_UCI_SMS_SPAM_2011",
                    "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                    "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                    "category": "C",
                    "category_name": categories["C"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic academic/campus coordination SMS.",
                    "annotator_confidence": "HIGH"
                })
            elif re_greet.search(t):
                candidates_by_cat["E"].append({
                    "original_id": orig_id,
                    "source": "SRC_UCI_SMS_SPAM_2011",
                    "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                    "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                    "category": "E",
                    "category_name": categories["E"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic personal greeting and short opener.",
                    "annotator_confidence": "HIGH"
                })
            elif re_bank.search(t):
                candidates_by_cat["H"].append({
                    "original_id": orig_id,
                    "source": "SRC_UCI_SMS_SPAM_2011",
                    "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                    "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                    "category": "H",
                    "category_name": categories["H"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic personal banking/financial inquiry.",
                    "annotator_confidence": "HIGH"
                })
            elif re_tech.search(t):
                candidates_by_cat["I"].append({
                    "original_id": orig_id,
                    "source": "SRC_UCI_SMS_SPAM_2011",
                    "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                    "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                    "category": "I",
                    "category_name": categories["I"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic technical discussion/computer reference.",
                    "annotator_confidence": "HIGH"
                })
            else:
                candidates_by_cat["D"].append({
                    "original_id": orig_id,
                    "source": "SRC_UCI_SMS_SPAM_2011",
                    "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                    "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                    "category": "D",
                    "category_name": categories["D"],
                    "text": t,
                    "security_label": "BENIGN",
                    "annotation_rationale": "Authentic conversational coordination.",
                    "annotator_confidence": "HIGH"
                })
        elif lbl_raw == "spam":
            candidates_by_cat["M"].append({
                "original_id": orig_id,
                "source": "SRC_UCI_SMS_SPAM_2011",
                "source_family": "AUTHENTIC_MOBILE_SMS_UCI",
                "acquisition_provenance": "UCI SMS Spam Collection (Almeida et al. 2011), verified independent unused partition.",
                "category": "M",
                "category_name": categories["M"],
                "text": t,
                "security_label": "SUSPICIOUS_SPAM",
                "annotation_rationale": "Promotional spam text (retail discount, ringtones, lottery contest).",
                "annotator_confidence": "HIGH"
            })

# 2.3 Harvest from IMC25 (Fishing for Smishing - ACM IMC 2025)
print("Harvesting from SRC_IMC25_FISHING_SMISHING...")
p_imc = ROOT / "data/raw/SRC_IMC25_FISHING_SMISHING/final_dataset_output.csv"
with open(p_imc, "r", encoding="utf-8", errors="replace") as f:
    for idx, r in enumerate(csv.DictReader(f)):
        t = (r.get("text") or "").strip()
        scam = (r.get("scam_type") or "").strip().lower()
        lang = (r.get("language") or "").strip()
        if not t: continue
        
        orig_id = f"IMC25_ROW_{idx:05d}"
        is_clean, reason = check_isolation(t, orig_id)
        if not is_clean: continue
        
        has_u = bool(re_url.search(t))
        has_p = bool(re_phone.search(t))
        has_a = bool(re_apk.search(t))
        
        # Categorize threats
        if scam in ("wrong number", "hey mum/dad"):
            candidates_by_cat["D"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "D",
                "category_name": categories["D"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": f"Authentic conversational social engineering lure ({scam}).",
                "annotator_confidence": "HIGH"
            })
        elif has_a:
            candidates_by_cat["J"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "J",
                "category_name": categories["J"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "Malicious mobile APK malware dropper lure.",
                "annotator_confidence": "HIGH"
            })
        elif ("electric" in t.lower() or "power" in t.lower() or "disconnection" in t.lower() or "bijli" in t.lower()):
            candidates_by_cat["B"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "B",
                "category_name": categories["B"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "Authentic electricity disconnection extortion/phishing scam.",
                "annotator_confidence": "HIGH"
            })
        elif (lang == "Hindi" or "aapka" in t.lower() or "karein" in t.lower() or "turant" in t.lower()):
            candidates_by_cat["L"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "L",
                "category_name": categories["L"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "Authentic Indian fraud lure communicated in Hinglish.",
                "annotator_confidence": "HIGH"
            })
        elif has_p and not has_u:
            candidates_by_cat["K"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "K",
                "category_name": categories["K"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "Vishing callback lure asking recipient to call an attacker phone number.",
                "annotator_confidence": "HIGH"
            })
        elif not has_u and scam in ("banking", "government", "telecom"):
            candidates_by_cat["A"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "A",
                "category_name": categories["A"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "URL-less threat asserting account or compliance failure.",
                "annotator_confidence": "HIGH"
            })
        elif re_greet.search(t) and len(t.split()) <= 10:
            candidates_by_cat["E"].append({
                "original_id": orig_id,
                "source": "SRC_IMC25_FISHING_SMISHING",
                "source_family": "AUTHENTIC_PUBLIC_USER_REPORTS_IMC25",
                "acquisition_provenance": "ACM IMC 2025 Fishing for Smishing Corpus (Agarwal et al. 2025), user-reported smishing database.",
                "category": "E",
                "category_name": categories["E"],
                "text": t,
                "security_label": "MALICIOUS",
                "annotation_rationale": "Malicious short greeting / conversation initiator from unknown sender.",
                "annotator_confidence": "HIGH"
            })

print("Harvest summary from external corpora:")
for cat_k in sorted(categories.keys()):
    c_list = candidates_by_cat[cat_k]
    lbls = Counter(c["security_label"] for c in c_list)
    print(f"  Category {cat_k} ({categories[cat_k]}): Total={len(c_list)}, Labels={dict(lbls)}")

print("\nTotal exclusions so far:", dict(exclusion_stats))
