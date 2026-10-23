"""Probe: do the observed failure texts / n-grams exist in the training corpus?"""
import hashlib, json, os, re, unicodedata

ML = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml"
INV = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation"
out = []
emit = out.append

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

emit("=== CHAMPION V2 ARTIFACT HASHES ===")
for fn in ["champion_v2_model.pkl", "champion_v2_scaler.pkl", "champion_v2_tfidf_word.pkl", "champion_v2_tfidf_char.pkl"]:
    p = os.path.join(ML, fn)
    emit(f"{fn:34s} {sha256(p) if os.path.exists(p) else 'MISSING'}")

def load(name):
    p = os.path.join(ML, "data", "processed", name)
    recs = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                recs.append(json.loads(line))
    return recs

splits = {}
for name in ["train.jsonl", "val.jsonl", "test.jsonl", "ood.jsonl", "train_expanded_v8.jsonl"]:
    try:
        splits[name] = load(name)
        emit(f"loaded {name}: {len(splits[name])}")
    except FileNotFoundError:
        emit(f"MISSING {name}")

def norm(t):
    t = unicodedata.normalize("NFKC", str(t)).lower()
    return re.sub(r"[^a-z0-9 ]+", " ", t)

def normkey(t):
    return re.sub(r" +", " ", norm(t)).strip()

def words(t):
    return set(norm(t).split())

inst_fp = [
    "Dear students, the university has partnered with Dell to offer discounted laptops. Check the campus store. Regards",
    "Hi everyone, our institution has procured new campus software licenses. Available next week.",
    "Infrastructure announcements: New campus Wi-Fi provided by Cisco. Available next week.",
    "Scholarship announcements: Our institution has provided new funds. Available to all students.",
    "IT announcements: Dear team, university email migration next week. Provided by IT.",
    "Library announcements: Dear students, our institution has partnered with JSTOR. Access provided",
]
inst_miss = [
    "College announcement: Faculty must install this .apk for new campus laptops next week.",
    "Corporate partnership: Microsoft requires you to update password immediately.",
    "Internship announcements: We have partnered with firms. Pay processing fee now.",
    "Event announcements: Campus festival next week. Buy tickets, UPI transfer required.",
    "Faculty notices: Next week meetings. Last chance to avoid account suspended.",
]
sim_fp = [
    "Dear Customer,\nAmazon Prime is included in your Jio plan. Activate now to enjoy Prime Video Originals",
    "Okay baad mein meeting run karke dikhana aur explain karna",
    "aaradhay and yashika: quality check + lesion segmentation model",
    "Meeting time? Link ka dekhte hai",
    "aur simulation code se bana sakte hai shayad toh github code mile ya fir ai se",
    "DR severity vala 8 nahi, 4-5 hai.. 2-3 ek hi model se ho jayenge separate nahi",
    "https://github.com/rsk97/Diabetic-Retinopathy-Detection",
    "https://drive.google.com/drive/folders/1b7CsAPxwJZupBE8d_WD",
    "Meeting hai na 10 bhaje?",
    "SENTINEL - SUNDAY SINOVA - SUNDAY",
    "Run kar sakte hai..like values change kar sakte hai",
    "Retina.. Diabetic retinopathy",
    "Raat ko jab sab free ho @all 9 baje chalega?",
    "Ha ha..voh toh aap bhej do..because protype link hai",
    "1. AI-Doctor Disagreement Alert Sometimes the AI and doctor may give differen",
    "Your order is out for delivery. Share delivery OTP with partner upon arrival",
]
GROUPS = {"INST_FP": inst_fp, "INST_MISS": inst_miss, "SIM_FP": sim_fp}

NGRAM_SETS = {
    "institutional": ["partnered", "procure", "available next week", "announcement", "scholarship", "campus drive"],
    "hinglish_chat": ["baje", "dekhte", "karke", "bhej", "chalega", "meeting"],
    "promo": ["amazon prime", "jio"],
    "delivery_otp": ["delivery otp", "out for delivery"],
}

# ---------- per-split n-gram presence by label ----------
emit("\n=== N-GRAM PRESENCE BY SPLIT x LABEL (docs containing) ===")
for name, recs in splits.items():
    by_label = {}
    for r in recs:
        by_label.setdefault(r.get("security_label", "?"), []).append(norm(r.get("raw_text", "")))
    emit(f"\n-- {name} --  " + ", ".join(f"{k}:{len(v)}" for k, v in sorted(by_label.items())))
    for gname, grams in NGRAM_SETS.items():
        row = []
        for lbl in ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"]:
            docs = by_label.get(lbl, [])
            per = [sum(1 for d in docs if g in d) for g in grams]
            row.append(f"{lbl[:4]}:" + "/".join(map(str, per)))
        emit(f"   {gname:14s} " + "  ".join(row) + "   grams=" + repr(grams))

# ---------- contamination: exact/near match of failure texts in splits ----------
emit("\n=== CONTAMINATION CHECK (failure texts vs splits) ===")
for gname, texts in GROUPS.items():
    emit(f"-- {gname} --")
    for t in texts:
        tk = normkey(t)
        w = words(t)
        found = []
        for name, recs in splits.items():
            hit = False
            for r in recs:
                if normkey(r.get("raw_text", "")) == tk:
                    found.append(f"{name}:EXACT({r.get('security_label')})")
                    hit = True
                    break
            if hit:
                break
        if not found:
            for name, recs in splits.items():
                hit = False
                for r in recs:
                    rw = words(r.get("raw_text", ""))
                    if w and rw:
                        inter = len(w & rw) / max(1, min(len(w), len(rw)))
                        if inter >= 0.85:
                            found.append(f"{name}:NEAR({inter:.2f},{r.get('security_label')})")
                            hit = True
                            break
                if hit:
                    break
        emit(f"   [{'|'.join(found) if found else 'ABSENT':60s}] {t[:70]!r}")

# ---------- language fields ----------
emit("\n=== LANGUAGE FIELDS IN SPLITS ===")
for name, recs in splits.items():
    langs = {}
    for r in recs:
        langs[str(r.get("language", "?"))] = langs.get(str(r.get("language", "?")), 0) + 1
    emit(f"{name:24s} {dict(sorted(langs.items(), key=lambda kv: -kv[1]))}")

with open(os.path.join(INV, "train_probe.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("written", len(out), "lines")