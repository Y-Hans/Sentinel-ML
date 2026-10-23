from preplib import *
import difflib
guard()
ad=ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageAdjudicator.kt'
na=ROOT/'sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzer.kt'
fusion=ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionEngine.kt'
coord=ROOT/'sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationAgentCoordinator.kt'
old={p:small(p) for p in [ad,na,fusion,coord]};newad=old[ad].replace('val isThreat: Boolean get() = isNonBenign','// A promotion remains non-benign metadata but is not a malicious alert.\n    val isThreat: Boolean get() = classIndex == 2')
needle='''                val isNonBenign = mlResult.isNonBenign
                val threshold = messageScanner.decisionThreshold'''
replacement='''                val isNonBenign = mlResult.isNonBenign
                val isMalicious = mlResult.isThreat
                val isSpam = mlResult.classIndex == 1
                val threshold = messageScanner.decisionThreshold'''
assert needle in old[na];newna=old[na].replace(needle,replacement)
newna=newna.replace('''                val mlScore = if (isNonBenign) {
''','''                val mlScore = if (isSpam) {
                    0.0f
                } else if (isMalicious) {
''',1)
newna=newna.replace('''                    pNonBenign >= 0.90f -> EvidenceSeverity.CRITICAL
                    isNonBenign -> EvidenceSeverity.HIGH
''','''                    isSpam -> EvidenceSeverity.INFO
                    isMalicious && pNonBenign >= 0.90f -> EvidenceSeverity.CRITICAL
                    isMalicious -> EvidenceSeverity.HIGH
''',1)
# isNonBenign local becomes unused; no change to result field, probabilities or decision boundary.
newna=newna.replace('                val isNonBenign = mlResult.isNonBenign\n','',1)
assert newad!=old[ad] and newna!=old[na]
patch=''
for p,new in [(ad,newad),(na,newna)]:
 rel=p.relative_to(ROOT/'sentinel-ai').as_posix();patch+=''.join(difflib.unified_diff(old[p].splitlines(True),new.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
write('PROPOSED_ANDROID_MALICIOUS_ONLY.patch',patch)
save('android_patch_preconditions.json',{'status':'PROPOSED_NOT_APPLIED_NOT_COMPILED','source_hashes':{p.relative_to(ROOT).as_posix():sha(p) for p in old},'proposed_changed_files':[p.relative_to(ROOT).as_posix() for p in [ad,na]],'proposed_diff_sha256':sha(OUT/'PROPOSED_ANDROID_MALICIOUS_ONLY.patch'),'unchanged':'classifier decision, thresholds, probabilities, fusion, URL code, contact/group rules, failure handling','apply_requires':'separate explicit Android patch + test authorization and exact source hash recheck'})
# Python arithmetic only: no classifier inference or Kotlin execution, fixed diagnostic vectors.
def classify(p,t=.61):return 0 if p[1]+p[2]<t else 2 if p[2]>=p[1] else 1
def score(p,patched=False):
 c=classify(p);pn=p[1]+p[2]
 if patched and c==1:return c,0.,'INFO'
 s=70+(pn-.61)/(.39)*30 if c!=0 else pn/.61*35
 return c,s,'CRITICAL' if pn>=.90 else 'HIGH' if c!=0 else 'LOW'
cases=[]
for name,p in [('spam_high',[.02,.95,.03]),('malicious_high',[.02,.03,.95]),('benign',[.95,.03,.02]),('spam_at_boundary',[.39,.61,0]),('malicious_at_boundary',[.39,0,.61]),('tie_boundary',[.39,.305,.305])]:
 oldc,oscore,osev=score(p);newc,nscore,nsev=score(p,True)
 # Isolated message evidence with unknown/no contact, no payload, no extra intent.
 def isolated(s,sev):return max(s*.95,90) if sev=='CRITICAL' else s*.95
 before=isolated(oscore,osev);after=isolated(nscore,nsev)
 assert oldc==newc
 if newc==1:assert after==0
 else:assert before==after
 cases.append({'case':name,'probabilities':p,'class_index':newc,'old_evidence_score':oscore,'proposed_evidence_score':nscore,'old_severity':osev,'proposed_severity':nsev,'isolated_old_fused_score':before,'isolated_proposed_fused_score':after,'isolated_old_alert_ge40':before>=40,'isolated_proposed_alert_ge40':after>=40,'status':'OBSERVED Python arithmetic; NOT Kotlin parity'})
save('android_policy_arithmetic.json',cases)
tests=[
['A1','MessageAdjudicatorMOnlyTest','tau .61 and .704; P=[.02,.95,.03]','class1; isNonBenign true; isThreat false; original probabilities unchanged'],
['A2','MessageAdjudicatorMOnlyTest','tau .61 and .704; P=[.02,.03,.95]','class2; isNonBenign true; isThreat true; same decision as baseline'],
['A3','MessageAdjudicatorMOnlyTest','below/at/above tau; equal S/M at boundary','retain benign boundary and MALICIOUS tie behavior; no threshold change'],
['N1','NotificationMOnlyPolicyTest','stub scanner SPAM; text ordinary catalogue; no URL or other attack evidence','MESSAGE_ML INFO, score0; fusedGREEN/ALLOW; no warning dispatch'],
['N2','NotificationMOnlyPolicyTest','same stub MALICIOUS; no other evidence; unknown contact','unchanged HIGH/CRITICAL evidence and warning; no malicious downgrade'],
['N3','NotificationMOnlyPolicyTest','SPAM + HIGH/CRITICAL URL payload, same URLs and stub URL scanner','URL analysis called; payload evidence/score preserved; warning/block still occurs; no early return on SPAM'],
['N4','NotificationMOnlyPolicyTest','SPAM + independent OTP disclosure/credential heuristic','independent malicious intent still alerts; SPAM itself contributes0. Do not globally suppress a notification merely because ML class1'],
['F1','Existing fusion contact/group tests + new metamorphic regression','Cartesian known/unknown contact × group/1:1 × SERVICE/GOVT/PROMO/MISSING header','group is not whitelist; high payload never suppressed; unchanged payload policy; no automatic immunity from header'],
['F2','Fusion metamorphic equality','append proposed INFO/score0 SPAM evidence to any existing valid evidence fixture','same final riskScore/riskLevel/decision; informational explanation may gain SPAM label; no new compounding'],
['F3','Failure regression','model throws, missing/corrupt assets, NaN/out-of-range probabilities','existing fail-closed unavailable evidence unchanged; never silently converted to SPAM-safe'],
['D1','Coordinator dispatch regression','isolated SPAM then MALICIOUS then SPAM+high payload result','zero warning for isolated SPAM; malicious/payload warning preserved; persistence still records all scans'],
['P1','Static change-scope/parity review','git diff + frozen model/scaler/vectorizer hashes after later authorized patch','only2production files plus new tests; no URL extractor/fusion/domain/threshold/model changes']]
csvwrite('PROPOSED_ANDROID_TEST_MATRIX.csv',[dict(zip(['id','proposed_test','input','expected'],r)) for r in tests])
write('ANDROID_PATCH_PROPOSAL.md','''# Minimal Messages alert-policy patch — NOT APPLIED

OBSERVED static finding: MessageAdjudicator.kt `isThreat` aliases `isNonBenign`. NotificationThreatAnalyzer.kt uses P(S)+P(M) and the non-benign flag to create HIGH/CRITICAL MESSAGE_ML evidence. RiskFusionEngine treats MESSAGE_ML as intent, applies evidence confidence and critical override; NotificationAgentCoordinator dispatches warnings for BLOCK or elevated warning severity. Source hashes and exact proposed diff are in android_patch_preconditions.json and PROPOSED_ANDROID_MALICIOUS_ONLY.patch. No source edits, Gradle, Kotlin execution or tests occurred.

OBSERVED Python-only illustration: at tau .61 and P(B,S,M)=(.02,.95,.03), class remains SPAM, but current evidence is CRITICAL; isolated fusion score >=90 and alert eligibility follows. The proposed branch gives INFO/score0. P=(.02,.03,.95) retains malicious evidence/decision unchanged. Exact arithmetic for6fixed vectors is in android_policy_arithmetic.json. This is a transcription check, not compilation or Android parity.

PROPOSED production scope: exactly2 files. In MessageScanResult, change isThreat to classIndex==2; retain isNonBenign and pNonBenign as descriptive metadata, classifier decisions and threshold. In NotificationThreatAnalyzer, class1 contributes score0 and INFO while class2 keeps the existing bands; benign branch remains unchanged. Keep the INFO item for logged class/probability visibility. Do not return early on SPAM; URL scanning, content heuristics and missing-model handling continue. No fusion or coordinator source edit is proposed. Do not modify URL-ML, safe-domain policy, contact/group policies or model assets.

PROPOSED semantic contract: SPAM model output alone never causes an alert. A notification with independently malicious URL/payload/credential evidence can still alert even if the message classifier says SPAM. Suppressing the entire scan based on class1 would violate payload overrides and is explicitly rejected. This patch does not promise that every real promotion avoids unrelated heuristic false positives; review those independently.

PROPOSED tests: PROPOSED_ANDROID_TEST_MATRIX.csv specifies12 test groups spanning model boundaries, notification evidence, fusion invariants, dispatch and fail-closed paths. Use existing JUnit4/scanner stubs and run existing fusion/notification/golden tests only after separate authorization. For unchanged contexts, compare before/after fixture decisions and payload evidence; do not assert all contacts have identical risk scores because existing contact dampening deliberately differs. Test INFO/score0 spam evidence as inert to scoring, not identical explanation text.

PROPOSED acceptance: all SPAM-only fixtures produce no warning; all prior malicious/payload fixtures retain protection; no group/contact or URL-policy regression; source hashes match the preconditions before applying. Rebase proposal if any target changed. Review and test permission is separate from model-fit approval. Android release remains NO-GO until the patch is separately approved, applied and tested. Current proposal is review-ready but uncompiled.
''')
print('proposal written; production edits 0; fixed Python arithmetic cases',len(cases))
