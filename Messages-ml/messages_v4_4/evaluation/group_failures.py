import json

def get_failure_mechanism(x):
    p_nb = x['probs']['exp3']
    if p_nb < 0.74:
        return f"Threshold Creep (Prob {p_nb:.3f} < 0.74)"
    else:
        return f"Class Confusion (Predicted SPAM instead of MALICIOUS)"

with open('forensic_test_results.json') as f: data = json.load(f)

groups = {"Threshold Creep": [], "Class Confusion": []}
for x in data['malicious_missed_newly']:
    mech = "Threshold Creep" if x['probs']['exp3'] < 0.74 else "Class Confusion"
    groups[mech].append(x)

print("FAILURE MECHANISMS")
for k, v in groups.items():
    print(f"\n=== {k} ({len(v)} examples) ===")
    for x in v[:5]:
        print(f"- {x['id']}: RC1 nb_prob={x['probs']['rc1']:.3f} -> Exp3 nb_prob={x['probs']['exp3']:.3f}")
        print(f"  Text: {x['text'][:80]}...")
