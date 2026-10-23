from sprintlib import *
guard()
rr=list(rows(OUT/'probe_v2.csv'));chosen=[r for r in rr if r['language']=='Hinglish' and r['expected']=='BENIGN' and r['channel_style']=='SMS'][:6];changed={r['id'] for r in chosen}|{r['english_twin_id'] for r in chosen if r['english_twin_id']}
for r in rr:
 if r['id'] in changed:r['channel_style']='WhatsApp';r['sender_header']=''
(OUT/'frozen').mkdir(exist_ok=False)
csvwrite('frozen/probe_v2.csv',rr)
byid={r['id']:r for r in rr};review=list(rows(OUT/'REVIEW_SAMPLE_v2.csv'))
csvwrite('frozen/REVIEW_SAMPLE_v2.csv',[{**byid[r['id']],'user_agree':'','user_note':''} for r in review])
write('frozen/PROBE_V2_DESIGN.md',small(OUT/'PROBE_V2_DESIGN.md')+'\nOBSERVED pre-freeze correction: the first generation had 206 SMS / 194 WhatsApp benign rows. The score-free validator rejected it. Six Hinglish benign metadata assignments and corresponding English twins were changed in this new file only; all texts and labels are identical. The original draft remains unmodified and was never scored. See repair_manifest.json.\n')
save('repair_manifest.json',{'reason':'33 per family yielded excess SMS benign metadata','changed_ids':sorted(changed),'text_changes':0,'label_changes':0,'scored_before_repair':False,'original_sha256':sha(OUT/'probe_v2.csv'),'corrected_sha256':sha(OUT/'frozen/probe_v2.csv')})
# Create new numbered scripts; the failed validator and unexecuted inference source remain unchanged.
s=small(OUT/'audit_freeze.py').replace("OUT/'probe_v2.csv'","OUT/'frozen/probe_v2.csv'").replace("'intra_probe_audit.json'","'intra_probe_audit_audit02.json'").replace("'PROBE_V2_DESIGN.md','probe_v2.csv','probe_v1_normalized.csv','REVIEW_SAMPLE_v2.csv'","'frozen/PROBE_V2_DESIGN.md','frozen/probe_v2.csv','probe_v1_normalized.csv','frozen/REVIEW_SAMPLE_v2.csv'").replace("'probe_v2.sha256'","'frozen/probe_v2.sha256'")
write('audit_freeze_02.py',s)
s=small(OUT/'inference.py').replace("OUT/'probe_v2.csv'","OUT/'frozen/probe_v2.csv'");write('inference_02.py',s)
print('corrected metadata',len(changed),'text and label changes 0')
