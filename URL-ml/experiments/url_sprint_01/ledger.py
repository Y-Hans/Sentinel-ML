from common import *
import ast,re,collections
from v7_features import V7_FEATURE_NAMES,extract_v7_features
paths=[U/'scripts/v7_features.py',U/'scripts/v8_normalization.py',U/'scripts/v8_classifier.py',ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlFeatureExtractor.kt',ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt']
sources={p.relative_to(ROOT).as_posix():readtext(p) for p in paths}
text=sources['sentinel-ml/URL-ml/scripts/v7_features.py'];tree=ast.parse(text)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='extract_v7_features')
assign={}
for n in fn.body:
    if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name):assign[n.targets[0].id]=ast.unparse(n.value)
ret=next(n.value for n in fn.body if isinstance(n,ast.Return))
expr={ast.literal_eval(k):ast.unparse(v) for k,v in zip(ret.keys,ret.values)}
def deps(s,seen=None):
    seen=set() if seen is None else seen
    for name in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b',s):
        if name in assign and name not in seen:
            seen.add(name);deps(assign[name],seen)
    return '; '.join(f'{n} = {assign[n]}' for n in sorted(seen))
pairs={'schemeless_to_https':('instagram.com','https://instagram.com'),'protocol_relative_to_https':('//instagram.com','https://instagram.com'),'www_to_apex':('https://www.instagram.com','https://instagram.com'),'root_slash_to_empty':('https://instagram.com/','https://instagram.com'),'host_case':('https://INSTAGRAM.COM','https://instagram.com'),'query_value_identity':('https://example.org/?q=cat','https://example.org/?q=dog'),'path_identity':('https://example.org/cat','https://example.org/dog')}
tests={name:(extract_v7_features(a),extract_v7_features(b)) for name,(a,b) in pairs.items()}
ledger=[]
for i,name in enumerate(V7_FEATURE_NAMES):
    group='interaction' if name.startswith('Risk_') else 'safe_context' if name.startswith('Safe_') else 'path' if name.startswith('Path') else 'query' if name.startswith('Query') else 'host' if name.startswith(('Host','Domain','Brand','Known','NoOfSub','SuspiciousTLD','IsDomain','IsIPv4')) else 'url_scheme'
    ledger.append(dict(index=i,feature=name,group=group,definition=expr[name],intermediate_definitions=deps(expr[name]),collapses_observed=';'.join(k for k,(a,b) in tests.items() if a[name]==b[name]),distinguishes_observed=';'.join(k for k,(a,b) in tests.items() if a[name]!=b[name]),source='sentinel-ml/URL-ml/scripts/v7_features.py',source_line=next(v.lineno for k,v in zip(ret.keys,ret.values) if ast.literal_eval(k)==name)))
csvout(OUT/'FEATURE_LEDGER.csv',ledger)
sets={}
for p in paths[:3]:
    t=ast.parse(readtext(p));constants={}
    for n in t.body:
        if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.isupper():
            try:
                val=ast.literal_eval(n.value)
                if isinstance(val,(set,tuple,list,dict)):constants[n.targets[0].id]=sorted(val) if not isinstance(val,dict) else val
            except (ValueError,TypeError):pass
    sets[p.relative_to(ROOT).as_posix()]=constants
js(OUT/'code_constants.json',sets)
kt=sources[paths[3].relative_to(ROOT).as_posix()]
ks={name:sorted(re.findall(r'"([^"\n]+)"',m.group(1))) for name in ('COMMON_BRANDS','TWO_LABEL_SUFFIXES','SUSPICIOUS_TLDS','SUSPICIOUS_WORDS','SUSPICIOUS_EXTENSIONS') if (m:=re.search(r'val '+name+r' = (?:setOf|arrayOf)\((.*?)\n    \)',kt,re.S))}
py=sets['sentinel-ml/URL-ml/scripts/v7_features.py']
diffs={n:{'python_only':sorted(set(py[n])-set(v)),'kotlin_only':sorted(set(v)-set(py[n]))} for n,v in ks.items()}
js(OUT/'static_parity.json',{'feature_names':V7_FEATURE_NAMES,'set_differences':diffs,'canonicalization_test_pairs':pairs,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in paths},'python_v7_v8_suffix_differences':sorted(set(sets['sentinel-ml/URL-ml/scripts/v8_normalization.py']['TWO_LABEL_SUFFIXES'])-set(py['TWO_LABEL_SUFFIXES']))})
md='''# Feature ledger — OBSERVED from code
The model contract is 67 names sorted alphabetically (CSV index is the actual model order, not dictionary insertion order). FEATURE_LEDGER.csv contains each exact expression, transitive intermediate definitions, source line, group, and measured collapse/distinguish flags. A flag is an equality on the concrete pair in static_parity.json, not a universal equivalence proof. Canonicalization merges schemeless and protocol-relative forms with https; it does not remove www. Host identity is otherwise compressed into lexical counts/entropy/brand heuristics: unrelated domains can collide. Path/query identity is largely lost beyond keywords, lengths, entropy and patterns. There is no ranking, live reputation, DNS, certificate, page content or destination resolution feature.

Parse definitions: raw is canonicalized trimmed input; p is urllib.parse.urlsplit; host is lowercase hostname with trailing dots removed; seg is nonempty slash-separated raw path segments; decoded_path is one urllib.unquote. clean_path_str rejoins seg with /. raw_len/host_len are floored at one. Entropy is base-2 empirical character Shannon entropy. _registrable_label and _subdomain_depth use the fixed v7 suffix table, not a complete public suffix list. Brand matching applies alphanumeric compaction, leet normalization, candidate tokens, substring similarity >=0.8, and one-edit similarity 0.85; known registrable brands return zero impersonation. Safe brand recognition matches a label, not verified domain ownership or TLD. code_constants.json lists all literal domain/brand/suffix/extension/word registries with their source module. Helpers and exact source hashes are recorded in static_parity.json. Read the intermediate formulas with these definitions.

Adjudicator execution order (OBSERVED): parse URL; derive platform flags (dev/gaming/media/docs/search); detect extension using feature OR path/query suffix checks; redirect feature OR path/query target checks; detect leet registrable-brand typo; derive verified-brand/Steam context; hostile-artifact and public Google docs/forms context; generic password/otp/credential harvest conditional on verification; query exploit/double encoding; financial sensitive path; YouTube @handle exception; aggregate feature/threat blockers. Then (1) impersonation/leet -> max(raw,0.95); else (2) suspicious extension -> max(raw,0.98); else (3) redirect/credential/exploit -> max(raw,0.95); else (4) verified brand with raw strictly below 0.28 and no blockers -> 0.001; otherwise passthrough. Final >=0.28 alerts. Suspicious TLD/IP/punycode/financial flags block discount but do not themselves force an override. conf_bound and many platform regexes are present but unused in current decision logic. No high-score route-shape suppression executes. The no-URL Python fallback only applies below-threshold safe-brand gating and never adds the URL-string threat overrides, so its alert decisions match raw at the frozen threshold.

Python/Kotlin visible divergences (static findings, no Kotlin execution):
- Kotlin URLDecoder converts + in paths to spaces; Python unquote preserves +. Malformed escapes are caught differently. Entropy can diverge.
- Kotlin uses UTF-16 Char counts/lengths; Python counts Unicode code points. Supplementary Unicode changes length, entropy and ratios; Unicode predicates need runtime parity tests.
- Kotlin isIpv6 tests only for a colon; Python ipaddress validates the address. Malformed colon hosts can diverge. Kotlin HasPort considers port 0 nonstandard; Python bool(port_val) excludes zero.
- Kotlin SafeDomainAdjudicator translateLeet handles 0/1/3/4/5, omitting Python 7/@; Kotlin feature extractor has its own mapping.
- Kotlin featureThreat wraps the whole OR in !(HasAt && isYoutubeHandle); Python exempts only its HasAt term. Other blockers can be masked for a YouTube handle in Kotlin (mandatory explicit overrides remain separate).
- Python V8 normalization adds com.tr/github.io/gitlab.io/pages.dev/web.app to v7 suffix handling. Kotlin feature extractor parentDomain returns the registrable label using the v7 table. Python adjudicator splits the V8 full parent at the first dot. Tenant and suffix boundary contexts can differ.
- Kotlin no-URL overload calls URL adjudication with an empty string; Python no-URL overload uses a vectorized fallback without mandatory feature overrides. They are different APIs.
- Both redirect feature regexes contain uppercase %3A/%2F while matching a lowercased query: encoded branch does not match; V8 URL adjudicator may recover it via other checks. Features remain frozen.

No parity fixes are made. A feature proposal would require updating Kotlin extraction and indices, portable metadata, malformed/Unicode/encoding parity fixtures, Android runtime cost and benchmarks; it is outside this sprint. Permutation results will be supplied separately from a domain-grouped clean-test sample using raw V8 average precision; correlated feature masking limits interpretation and importance does not establish causality.

| Index | Feature | Group | Exact expression |
|---|---|---|---|
'''
md+='\n'.join(f"| {r['index']} | {r['feature']} | {r['group']} | `{r['definition']}` |" for r in ledger)+'\n'
write(OUT/'FEATURE_LEDGER.md',md)
print('ledger',len(ledger),'features',flush=True)
