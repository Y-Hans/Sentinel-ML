"""Full-corpus V4.3 composition, stratification, calibration and label audit.

Read-only over training and protected evaluation files. Writes only the seven
SECOND ML forensic deliverables at Messages-ml root.
"""
import hashlib, json, math, pickle, re, sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import log_loss

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "messages_v4_3" / "models"))
from candidate_d_v4_3 import extract_structural_signals  # noqa: E402

ART = ROOT / "messages_v4_3" / "models" / "candidate_d"
LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
REV = {v: k for k, v in LABELS.items()}
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
PHONE_RE = re.compile(r"(?:\+91|0)?[6-9]\d{9}")
SPLITS = {"TRAIN": ROOT / "messages_v4_3/data/train_v4_3.jsonl",
          "VAL": ROOT / "data/processed/val.jsonl", "TEST": ROOT / "data/processed/test.jsonl",
          "OOD": ROOT / "data/processed/ood.jsonl"}
FIELDS = {"source_id": "source_id", "source_type": "source_type", "language": "language",
          "script": "script", "category": "primary_type", "intent": "primary_type", "source_scam_type": "source_scam_type", "threat_vector": "threat_vectors"}
TERMS = {
    "hello": re.compile(r"\bhello\b", re.I), "hi": re.compile(r"\bhi\b", re.I),
    "electricity": re.compile(r"\belectricity\b", re.I), "meter": re.compile(r"\bmeter\b", re.I),
    "bill": re.compile(r"\bbill\b", re.I), "otp": re.compile(r"\botp\b", re.I),
    "apk": re.compile(r"\.apk\b", re.I), "phone_or_call": re.compile(r"\b(?:phone|call|dial|contact)\b", re.I),
    "institutional": re.compile(r"\b(?:college|university|student|faculty|campus|department|workspace|microsoft|dell|hp)\b", re.I),
    "promotional": re.compile(r"\b(?:free|offer|win|won|reward|prize|cashback|discount|bonus|claim)\b", re.I),
    "account_security": re.compile(r"\b(?:account|security|verify|verification|suspend|blocked|password|pin|login)\b", re.I),
}
PROMO_RE = re.compile(r"\b(?:free|offer|win|won|reward|prize|cashback|discount|bonus|claim)\b", re.I)
SECURITY_RE = re.compile(r"\b(?:otp|password|pin|account|verify|verification|suspend|blocked|security|login)\b", re.I)
ACTION_RE = re.compile(r"\b(?:share|send|reply|provide|forward|click|install|download|pay|call|contact|transfer)\b", re.I)


def read(path):
    with open(path, encoding="utf-8") as f: return [json.loads(s) for s in f if s.strip()]


def group_value(row, field):
    if field == "source_scam_type":
        pm=row.get("provenance_metadata") or {}
        return [str(pm.get("scam_type") or "UNKNOWN")]
    if field == "threat_vector":
        vals = row.get("threat_vectors") or row.get("threat_vector") or ["UNANNOTATED"]
        if isinstance(vals, str): vals = [vals]
        return sorted({str(x) for x in vals}) or ["UNKNOWN"]
    return [str(row.get(FIELDS[field]) or "UNKNOWN")]


def distribution(values):
    c = Counter(values); n = len(values)
    return {k: {"count": int(v), "percent": float(100*v/n) if n else None} for k,v in sorted(c.items())}


def quantiles(values):
    a = np.asarray(values, dtype=float)
    return {f"p{int(q*100)}": float(np.quantile(a,q)) for q in (0,.25,.5,.75,.9,.95,.99,1)} if len(a) else {}


def load_model():
    with open(ART/"model.pkl","rb") as f: m=pickle.load(f)
    with open(ART/"scaler.pkl","rb") as f: s=pickle.load(f)
    with open(ART/"word_vec.pkl","rb") as f: w=pickle.load(f)
    with open(ART/"char_vec.pkl","rb") as f: c=pickle.load(f)
    return m,s,w,c


def predict(rows, model, scaler, word, char):
    texts=[r.get("raw_text","") for r in rows]
    st=np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    x=np.hstack([st,word.transform(texts).toarray(),char.transform(texts).toarray()]).astype(np.float32)
    p=model.predict_proba(scaler.transform(x)); pnb=p[:,1]+p[:,2]
    pred=np.where(pnb>=.61,np.where(p[:,2]>=p[:,1],2,1),0)
    return p,pnb,pred,st


def composition(rows):
    texts=[r.get("raw_text","") for r in rows]
    labels=[r.get("security_label","UNKNOWN") for r in rows]
    scripts=Counter()
    for r,t in zip(rows,texts):
        meta=str(r.get("script") or "UNKNOWN"); scripts["metadata:"+meta]+=1
        if any('\u0900'<=ch<='\u097f' for ch in t): scripts["observed:DEVANAGARI"]+=1
        elif any('\u0980'<=ch<='\u0dff' for ch in t): scripts["observed:OTHER_INDIC"]+=1
        elif any(ch.isalpha() for ch in t): scripts["observed:LATIN_OR_OTHER"]+=1
        else: scripts["observed:NO_ALPHA"]+=1
    out={"N":len(rows),"label_distribution":distribution(labels)}
    for name,field in FIELDS.items():
        vals=[]
        for r in rows: vals.extend(group_value(r,name))
        out[name+"_distribution"]=distribution(vals)
    out["script_distribution"]=distribution([f"metadata:{r.get('script') or 'UNKNOWN'}" for r in rows])
    out["observed_script_presence_counts"]={k:int(v) for k,v in sorted(scripts.items())}
    out["url_presence"]={"raw_model_regex":distribution(["YES" if URL_RE.search(t) else "NO" for t in texts]),
                         "normalized_url_placeholder":distribution(["YES" if re.search(r"<URL>",t,re.I) else "NO" for t in texts])}
    out["phone_presence"]={"raw_model_regex":distribution(["YES" if PHONE_RE.search(t) else "NO" for t in texts]),
                           "normalized_phone_placeholder":distribution(["YES" if re.search(r"<(?:PHONE|PHONE_NUMBER)>",t,re.I) else "NO" for t in texts])}
    out["message_length_chars"]={"overall":quantiles([len(t) for t in texts]),
                                  "by_label":{lab:quantiles([len(r.get('raw_text','')) for r in rows if r.get('security_label')==lab]) for lab in LABELS}}
    out["by_label"]={}
    for lab in LABELS:
        subset=[r for r in rows if r.get("security_label")==lab]; stxt=[r.get("raw_text","") for r in subset]
        item={"N":len(subset)}
        for name in FIELDS:
            vals=[]
            for r in subset: vals.extend(group_value(r,name))
            item[name+"_distribution"]=distribution(vals)
        item["raw_model_url_presence"]=distribution(["YES" if URL_RE.search(t) else "NO" for t in stxt])
        item["url_placeholder_presence"]=distribution(["YES" if re.search(r"<URL>",t,re.I) else "NO" for t in stxt])
        item["raw_model_phone_presence"]=distribution(["YES" if PHONE_RE.search(t) else "NO" for t in stxt])
        item["phone_placeholder_presence"]=distribution(["YES" if re.search(r"<(?:PHONE|PHONE_NUMBER)>",t,re.I) else "NO" for t in stxt])
        item["message_length_chars"]=quantiles([len(t) for t in stxt])
        out["by_label"][lab]=item
    out["intent_field_note"]="The schema/taxonomy defines primary_type as intent categories independent of security status. Both category and intent distributions map to this same stored field; they are not independent annotations. There is no separate populated intent property. source_scam_type is a source-provided scam-family proxy, not a normalized intent. threat_vectors is an array and records are multi-counted across its values."
    return out


def metrics_for(indices, y, pred):
    idx=np.asarray(indices,dtype=int)
    if not len(idx): return {"N":0}
    yt=y[idx]; yp=pred[idx]
    nb=int((yt==0).sum()); nm=int((yt==2).sum()); ns=int((yt==1).sum())
    return {"N":int(len(idx)),"BENIGN":nb,"SUSPICIOUS_SPAM":ns,"MALICIOUS":nm,
        "benign_FP":int(((yt==0)&(yp!=0)).sum()),"benign_FPR":float(((yt==0)&(yp!=0)).sum()/nb) if nb else None,
        "malicious_correct":int(((yt==2)&(yp==2)).sum()),"malicious_recall":float(((yt==2)&(yp==2)).sum()/nm) if nm else None,
        "spam_to_malicious":int(((yt==1)&(yp==2)).sum()),"malicious_to_spam":int(((yt==2)&(yp==1)).sum()),
        "malicious_to_benign":int(((yt==2)&(yp==0)).sum())}


def error_strata(rows,y,p,pnb,pred,st):
    out={}; fields=list(FIELDS)+["url_presence","phone_presence"]
    for field in fields:
        groups=defaultdict(list)
        for i,r in enumerate(rows):
            if field=="url_presence":
                t=r.get("raw_text",""); vals=["RAW_URL" if URL_RE.search(t) else "PLACEHOLDER_ONLY" if re.search(r"<URL>",t,re.I) else "NO_URL"]
            elif field=="phone_presence":
                t=r.get("raw_text",""); vals=["RAW_PHONE" if PHONE_RE.search(t) else "PLACEHOLDER_ONLY" if re.search(r"<(?:PHONE|PHONE_NUMBER)>",t,re.I) else "NO_PHONE"]
            else: vals=group_value(r,field)
            for v in vals: groups[v].append(i)
        out[field]={}
        for k,idx in sorted(groups.items()):
            m=metrics_for(idx,y,pred)
            ii=np.asarray(idx,dtype=int)
            m["mean_probabilities_by_true_label"]={REV[c]:[float(x) for x in p[ii[y[ii]==c]].mean(axis=0)] for c in range(3) if (y[ii]==c).any()}
            m["mean_p_nonbenign_by_true_label"]={REV[c]:float(pnb[ii[y[ii]==c]].mean()) for c in range(3) if (y[ii]==c).any()}
            out[field][k]=m
    return out


def calibration(rows,p,pnb,pred):
    y=np.asarray([LABELS[r['security_label']] for r in rows],dtype=int)
    yth=(y!=0).astype(int); bins=np.linspace(0,1,11); table=[]; ece=0
    for lo,hi in zip(bins[:-1],bins[1:]):
        mask=(pnb>=lo)&((pnb<hi) if hi<1 else (pnb<=hi))
        n=int(mask.sum())
        if not n: table.append({"lower":float(lo),"upper":float(hi),"N":0}); continue
        conf=float(pnb[mask].mean()); rate=float(yth[mask].mean()); ece+=n/len(y)*abs(conf-rate)
        table.append({"lower":float(lo),"upper":float(hi),"N":n,"mean_p_nonbenign":conf,"observed_nonbenign_rate":rate})
    onehot=np.eye(3)[y]
    classwise={}
    for c in range(3):
        target=(y==c).astype(int); pc=p[:,c]; ce=0; binsc=[]
        for lo,hi in zip(bins[:-1],bins[1:]):
            mask=(pc>=lo)&((pc<hi) if hi<1 else (pc<=hi)); n=int(mask.sum())
            if n:
                conf=float(pc[mask].mean()); obs=float(target[mask].mean()); ce+=n/len(y)*abs(conf-obs)
                binsc.append({"lower":float(lo),"upper":float(hi),"N":n,"mean_probability":conf,"observed_rate":obs})
            else: binsc.append({"lower":float(lo),"upper":float(hi),"N":0})
        classwise[REV[c]]={"one_vs_rest_brier":float(np.mean((pc-target)**2)),"one_vs_rest_ECE_10_bins":float(ce),"reliability_bins":binsc}
    return {"split":"VAL only","multiclass_brier_mean_over_class_dimensions":float(np.mean(np.sum((p-onehot)**2,axis=1))),
        "multiclass_log_loss":float(log_loss(y,p,labels=[0,1,2])),"binary_nonbenign_brier":float(np.mean((pnb-yth)**2)),
        "binary_nonbenign_log_loss":float(-np.mean(yth*np.log(np.clip(pnb,1e-15,1))+(1-yth)*np.log(np.clip(1-pnb,1e-15,1)))),
        "binary_nonbenign_ECE_10_equal_width_bins":float(ece),"reliability_bins":table,"classwise_one_vs_rest_calibration":classwise,
        "p_nonbenign_quantiles":quantiles(pnb),
        "probability_saturation":{"p_nonbenign_ge_0_99":float(np.mean(pnb>=.99)),"p_nonbenign_ge_0_999":float(np.mean(pnb>=.999)),
          "p_nonbenign_le_0_01":float(np.mean(pnb<=.01)),"any_class_probability_ge_0_999":float(np.mean(p.max(axis=1)>=.999)),
          "mean_max_class_probability":float(p.max(axis=1).mean())},
        "p_nonbenign_by_true_label":{REV[c]:quantiles(pnb[y==c]) for c in range(3)},
        "mean_probabilities_by_true_label":{REV[c]:[float(x) for x in p[y==c].mean(axis=0)] for c in range(3)},
        "confusion_conditional_probabilities":{f"{REV[a]}_pred_{REV[b]}":{"N":int(((y==a)&(pred==b)).sum()),
          "mean_probabilities":[float(x) for x in p[(y==a)&(pred==b)].mean(axis=0)],
          "quantiles_p_benign":quantiles(p[(y==a)&(pred==b),0]),"quantiles_p_spam":quantiles(p[(y==a)&(pred==b),1]),
          "quantiles_p_malicious":quantiles(p[(y==a)&(pred==b),2]),"quantiles_p_nonbenign":quantiles(pnb[(y==a)&(pred==b)])}
          for a,b in [(1,2),(2,1),(2,0)]}}


def confusion_probability_summary(rows,p,pnb,pred):
    y=np.asarray([LABELS[r['security_label']] for r in rows],dtype=int)
    out={}
    for a,b in [(1,2),(2,1),(2,0)]:
        m=(y==a)&(pred==b)
        out[f"{REV[a]}_pred_{REV[b]}"]={"N":int(m.sum()),
          "mean_probabilities":[float(x) for x in p[m].mean(axis=0)] if m.any() else None,
          "p_benign_quantiles":quantiles(p[m,0]),"p_spam_quantiles":quantiles(p[m,1]),
          "p_malicious_quantiles":quantiles(p[m,2]),"p_nonbenign_quantiles":quantiles(pnb[m])}
    return out


def probability_distribution(rows,p,pnb,pred):
    y=np.asarray([LABELS[r['security_label']] for r in rows]); out={"all":{}}
    out["all"]={"p_nonbenign":quantiles(pnb),"class_probability_quantiles":{REV[c]:quantiles(p[:,c]) for c in range(3)},
       "fraction_p_nonbenign_ge_0_99":float(np.mean(pnb>=.99),),"fraction_p_nonbenign_ge_0_999":float(np.mean(pnb>=.999)),
       "fraction_any_class_ge_0_999":float(np.mean(p.max(axis=1)>=.999))}
    out["by_true_label"]={}
    for c in range(3):
        mask=y==c; out["by_true_label"][REV[c]]={"N":int(mask.sum()),"p_nonbenign":quantiles(pnb[mask]),
           "class_probability_quantiles":{REV[k]:quantiles(p[mask,k]) for k in range(3)},
           "mean_probabilities":[float(z) for z in p[mask].mean(axis=0)]}
    return out


def main():
    model,scaler,word,char=load_model()
    ds={k:read(v) for k,v in SPLITS.items()}
    comp={k:composition(v) for k,v in ds.items()}
    def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    audit={"status":"REPRODUCED from full original JSONL files; no error-export sampling",
       "files":{k:str(v.relative_to(ROOT)) for k,v in SPLITS.items()},"threshold_fixed":0.61,
       "sha256":{"datasets":{k:sha(v) for k,v in SPLITS.items()},"v43_artifacts":{p.name:sha(p) for p in sorted(ART.glob("*.pkl"))}},
       "artifact_properties":{"class_order":[int(v) for v in model.classes_],"n_features_in":int(model.n_features_in_),"n_iter":int(model.n_iter_),"max_iter":int(model.max_iter),"early_stopping":model.early_stopping},
       "composition":comp,"error_stratification":{},"calibration_val_only":None,"split_metrics":{},"probability_distributions":{}}
    preds={}
    for split in ("VAL","TEST","OOD"):
        rows=ds[split]; p,pnb,pred,st=predict(rows,model,scaler,word,char); y=np.asarray([LABELS[r['security_label']] for r in rows])
        preds[split]=(p,pnb,pred,st,y)
        audit["split_metrics"][split]=metrics_for(range(len(rows)),y,pred)
        audit["probability_distributions"][split]=probability_distribution(rows,p,pnb,pred)
        if split in ("TEST","OOD"):
            audit["error_stratification"][split]=error_strata(rows,y,p,pnb,pred,st)
    audit["calibration_val_only"]=calibration(ds["VAL"],*preds["VAL"][:3])
    audit["class_confusion_probability_distributions"]= {}
    for split in ("TEST","OOD"):
        p,pnb,pred,st,y=preds[split]; audit["class_confusion_probability_distributions"][split]=confusion_probability_summary(ds[split],p,pnb,pred)
    audit["training_keyword_audit"]={}
    train=ds["TRAIN"]; yt=np.asarray([LABELS[r['security_label']] for r in train]); total=Counter(yt)
    for name,pat in TERMS.items():
        inds=[i for i,r in enumerate(train) if pat.search(r.get("raw_text",""))]
        by=Counter(yt[inds]); audit["training_keyword_audit"][name]={"N":len(inds),"label_counts":{REV[c]:int(by[c]) for c in range(3)},
          "label_rates_among_hits":{REV[c]:float(by[c]/len(inds)) for c in range(3)} if inds else {},
          "hit_rate_within_each_label":{REV[c]:float(by[c]/total[c]) for c in range(3)}}
    audit["label_semantics_heuristics"]={}
    for name,maskfn in {
      "malicious_promotional_wording":lambda t: bool(PROMO_RE.search(t)),
      "malicious_promotional_without_raw_url_or_phone":lambda t: bool(PROMO_RE.search(t)) and not URL_RE.search(t) and not PHONE_RE.search(t),
      "malicious_security_terms":lambda t: bool(SECURITY_RE.search(t)),
      "malicious_security_without_action_verb":lambda t: bool(SECURITY_RE.search(t)) and not ACTION_RE.search(t),
      "benign_security_terms":lambda t: bool(SECURITY_RE.search(t)),
      "url_less_malicious_conversational_short_le_8_words":lambda t: (not URL_RE.search(t) and not PHONE_RE.search(t) and len(t.split())<=8),
    }.items():
        # report each label separately; heuristics are literal regex indicators, not adjudication
        vals={lab:[r for r in train if r.get("security_label")==lab and maskfn(r.get("raw_text",""))] for lab in LABELS}
        audit["label_semantics_heuristics"][name]={lab:{"N":len(rr),"examples":[{"source_id":r.get("source_id"),"primary_type":r.get("primary_type"),"text":r.get("raw_text","")} for r in rr[:12]]} for lab,rr in vals.items()}
    # Distribution comparison uses full datasets, and conditional label rates for each key semantic term.
    audit["dataset_label_mix_comparison"]={s:comp[s]["label_distribution"] for s in comp}
    schema=json.load(open(ROOT/"data/schemas/message_record_schema.json",encoding="utf-8"))
    taxonomy=json.load(open(ROOT/"data/schemas/taxonomy.json",encoding="utf-8"))
    enums={"primary_type_schema":set(schema["properties"]["primary_type"]["enum"]),
           "primary_type_taxonomy":set(taxonomy["primary_types"]["categories"]),
           "threat_vectors_schema":set(schema["properties"]["threat_vectors"]["items"]["enum"]),
           "threat_vectors_taxonomy":set(taxonomy["threat_vectors"]["categories"]),
           "language_schema":set(schema["properties"]["language"]["enum"]),
           "source_type_schema":set(schema["properties"]["source_type"]["enum"])}
    audit["annotation_taxonomy_audit"]={}
    for label, allowed in enums.items():
        field="primary_type" if label.startswith("primary_type") else "threat_vectors" if label.startswith("threat_vectors") else "language" if label=="language_schema" else "source_type"
        observed=Counter(); out=defaultdict(Counter); split_out={}; unannotated={}
        for split,rows in ds.items():
            split_out[split]=Counter(); unannotated[split]=0
            for r in rows:
                if field=="threat_vectors" and not (r.get(field) or r.get("threat_vector")):
                    unannotated[split]+=1
                    continue
                vals=(r.get(field) or ["UNKNOWN"]) if field=="threat_vectors" else [str(r.get(field) or "UNKNOWN")]
                if isinstance(vals,str): vals=[vals]
                for v in vals:
                    observed[str(v)]+=1
                    if str(v) not in allowed:
                        out[str(v)][r.get("security_label","UNKNOWN")]+=1; split_out[split][str(v)]+=1
        audit["annotation_taxonomy_audit"][label]={"schema_or_taxonomy_allowed_values":sorted(allowed),"observed_values_with_counts":{k:int(v) for k,v in sorted(observed.items())},
          "observed_values_outside_allowed_set":{k:{"count":int(sum(v.values())),"by_security_label":{lab:int(v[lab]) for lab in sorted(v)}} for k,v in sorted(out.items())},
          "outside_allowed_counts_by_split":{s:{k:int(v) for k,v in sorted(c.items())} for s,c in split_out.items()},
          "unannotated_rows_by_split":unannotated,
          "allowed_but_not_observed":sorted(allowed-set(observed))}
    (ROOT/"DATASET_COMPOSITION_AUDIT.json").write_text(json.dumps(audit,ensure_ascii=False,indent=2),encoding="utf-8")
    print("wrote DATASET_COMPOSITION_AUDIT.json")
    print(json.dumps({"split_metrics":audit["split_metrics"],"val_calibration":audit["calibration_val_only"],"sources":{s:comp[s]["source_id_distribution"] for s in ("VAL","TEST","OOD")}},ensure_ascii=False,indent=2))


if __name__=="__main__": main()
