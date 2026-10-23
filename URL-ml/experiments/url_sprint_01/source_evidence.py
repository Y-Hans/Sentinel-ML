from common import *
import re,collections
evidence=[]
for pattern in ('PHASE_1C_*.md','PHASE_1D_*.md'):
    for p in sorted((U/'reports').glob(pattern)):
        t=readtext(p);lines=t.splitlines()
        candidates=[(i+1,line) for i,line in enumerate(lines) if re.search(r'REJECT|HARD_FAIL|regression|recall|Gate 5|denominator|contradict|98\.605|0\.962',line,re.I)]
        evidence.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size,'lines':len(lines),'status':'REPORTED historical evidence; not a current measurement','selected_excerpts':[{'line':i,'text':line[:1600]} for i,line in candidates[:10]]})
js(OUT/'historical_report_evidence.json',evidence)
ktpaths=[ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlFeatureExtractor.kt',ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt']
constants={}
for p in ktpaths:
    text=readtext(p)
    sets={m.group(1):re.findall(r'"([^"\n]+)"',m.group(2)) for m in re.finditer(r'val ([A-Z_]+) = (?:setOf|arrayOf)\((.*?)\n\s*\)',text,re.S)}
    constants[p.relative_to(ROOT).as_posix()]={'sha256':sha(p),'literal_sets':sets,'fixed_indices':{m.group(1):int(m.group(2)) for m in re.finditer(r'val (idx\w+) = (\d+)',text)}}
js(OUT/'kotlin_code_constants.json',constants)
write(OUT/'HISTORICAL_EVIDENCE_NOTES.md','''# REPORTED prior evidence and conflicts
historical_report_evidence.json reads every PHASE_1C_*/PHASE_1D_* markdown under URL-ml/reports below 1 MB and records hashes, lines and selected excerpts. No old experiment is rerun. No proposed fit code is executed. Current measurements are separate.

- Track A bare-apex report: benign apex 200/200 false alerts -> 8/200, but clean recall 98.605% ->97.405%, apex-attack recall 98.025% ->92.055%. Reject the strategy of benign-only apex augmentation.
- S2-E report: overall recall 97.543%, 8 golden regressions. The original Gate 5 denominator was wrong. Its correction addendum distinguishes the intended 4,254 apex attacks (V8 normalization) from 4,217 (v7 table), including 37 com.tr differences. Treat the original ~23k denominator and its apparent gate pass as invalid, not evidence that apex recall was retained. Reports also differ on Track A benign apex errors (6 versus 8); preserve as report/configuration differences.
- Threshold-only A1/A2 report: thresholds .55/.65 barely repair saturated benign roots and lose attacks; A2 has a golden output regression. Do not repeat scalar threshold modulation on a hostname shape.
- B1 report: a 16-token threat dictionary recovers only one clean-test TP and does not solve bare-apex false alerts. Its reported baseline 304/500 and 197/200 is different from 1C.1's frozen-model 420/500 and 200/200. Do not silently reconcile those configurations or use B1's figures as current V8 results.
- Some prior narrative calls known legitimate high-score roots hostile because their golden output label is MALICIOUS. A frozen output fixture encodes runtime parity, not externally established threat truth. Report output regressions separately from factual URL safety and never use model scores as training labels.
- Current export_v8_joblib.py wraps the V7 base estimator. Current train_v8_candidates.py also explores 83-feature models; it is not evidence for changing this sprint's frozen 67-feature contract. Historical input files and export source are not a complete row-level training manifest.

Kotlin constants are copied to kotlin_code_constants.json as code evidence only. Feature registry literal sets match Python v7 (static comparison); parse/adjudicator differences remain as described in FEATURE_LEDGER.md. No compilation/runtime verification is claimed.
''')
print('historical reports read',len(evidence),flush=True)
