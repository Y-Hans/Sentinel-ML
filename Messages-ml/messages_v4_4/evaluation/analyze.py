import json
with open('forensic_test_results.json') as f: data = json.load(f)

print("MISSED (RC1 -> Exp3)")
for x in data['malicious_missed_newly']:
    print(f"{x['id']} - RC1:{x['probs']['rc1']:.3f} -> Exp3:{x['probs']['exp3']:.3f} | V4.3:{x['probs']['v43']:.3f}")
    print(f"   Text: {x['text']}")
    print(f"   Signals: {', '.join(k for k, v in x['signals'].items() if v)}")
    print()

print("CAUGHT (RC1 -> Exp3)")
for x in data['malicious_caught_newly']:
    print(f"{x['id']} - RC1:{x['probs']['rc1']:.3f} -> Exp3:{x['probs']['exp3']:.3f}")
    print(f"   Text: {x['text']}")
    print()
