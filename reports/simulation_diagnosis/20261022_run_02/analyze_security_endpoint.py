from runlib import *
protect()
s=(OUT/'analyze.py').read_text(encoding='utf-8')
s=s.replace("'alert':p[mode+'_alert']","'alert':int(p[mode+'_class']==2) if track=='messages' else p[mode+'_alert']")
for name in ('metrics_summary.jsonl','segment_metrics.jsonl','worst_failures.jsonl','logged_comparison.jsonl','calibration_reliability.jsonl','threshold_sensitivity.jsonl','policy_changes.jsonl','analysis_counts.json'): s=s.replace("'"+name+"'","'security_"+name+"'")
exec(compile(s,'analyze.py (malicious-class endpoint)','exec'))
