import json

data = json.load(open('sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/s2_e_execution_metrics.json'))

corpora = ['clean_test', 'test_subgroup_malicious_apex', 'benchmark_bare_apex', 'benchmark_overall', 'adversarial_split', 'golden_fixtures', 'validation']

for c in corpora:
    print(f"==================== {c} ====================")
    for model in ['v8_eval', 'c0_eval', 'candidate_eval']:
        res = data[model][c]
        raw = res['raw_scores']
        adj = res['adjudicated_scores']
        m_name = model.replace('_eval', '').upper()
        print(f"Model: {m_name}")
        print(f"  Raw:         TP={raw['tp']:5d}, FP={raw['fp']:5d}, TN={raw['tn']:5d}, FN={raw['fn']:5d} | Rec={raw['recall']*100:.3f}% ({raw['tp']}/{raw['tp']+raw['fn']}) | FPR={raw['fpr']*100:.3f}% ({raw['fp']}/{raw['fp']+raw['tn']}) | 95% CI Rec: [{raw['recall_95ci'][0]*100:.3f}%, {raw['recall_95ci'][1]*100:.3f}%]")
        print(f"  Adjudicated: TP={adj['tp']:5d}, FP={adj['fp']:5d}, TN={adj['tn']:5d}, FN={adj['fn']:5d} | Rec={adj['recall']*100:.3f}% ({adj['tp']}/{adj['tp']+adj['fn']}) | FPR={adj['fpr']*100:.3f}% ({adj['fp']}/{adj['fp']+adj['tn']}) | 95% CI Rec: [{adj['recall_95ci'][0]*100:.3f}%, {adj['recall_95ci'][1]*100:.3f}%]")
        if 'regressions_count' in res:
            print(f"  Golden Regressions: {res['regressions_count']}")
