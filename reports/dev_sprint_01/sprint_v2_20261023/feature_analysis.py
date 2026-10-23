from sprintlib import *
guard()
from runtime import *
from feature_extraction import get_feature_names
from sender_parser import parse_sender_header
import ctypes,struct,random
t0=time.time()
# Native read-only CPU topology, fallback remains one inference thread.
try:
 length=ctypes.c_ulong(0);api=ctypes.windll.kernel32.GetLogicalProcessorInformationEx
 api(0,None,ctypes.byref(length));buf=ctypes.create_string_buffer(length.value)
 assert api(0,buf,ctypes.byref(length));pos=0;cores=0
 while pos<length.value:
  relation,size=struct.unpack_from('II',buf.raw,pos);cores+=relation==0;pos+=size
 topology={'physical_cores':cores,'fit_thread_cap':max(1,cores//2),'method':'Windows GetLogicalProcessorInformationEx(RelationProcessorCore)','inference_threads':1}
except Exception as e:topology={'physical_cores':None,'fit_thread_cap':1,'inference_threads':1,'error':repr(e)}
save('cpu_topology.json',topology)
loaded,meta=bundles();names2=get_feature_names();names43=['message_length','word_count','avg_word_length','digit_count','digit_ratio','uppercase_count','uppercase_ratio','special_char_count','special_char_ratio','url_count','has_url','phone_count','has_phone','is_question','is_short','is_naked_url','has_suspicious_tld','has_hex_or_ip_url','is_suspicious_naked_url']
fsrc=small(M/'scripts/feature_extraction.py');ftree=ast.parse(fsrc);defs={};groups={};regex={}
import feature_extraction as fe
for key,value in vars(fe).items():
 if isinstance(value,re.Pattern):regex[key]=value.pattern
for func in ftree.body:
 if not isinstance(func,ast.FunctionDef) or not func.name.startswith('extract_'):continue
 assignments={t.id:ast.unparse(n.value) for n in ast.walk(func) if isinstance(n,ast.Assign) for t in n.targets if isinstance(t,ast.Name)}
 for n in ast.walk(func):
  if isinstance(n,ast.Return) and isinstance(n.value,ast.Dict):
   for key,value in zip(n.value.keys,n.value.values):
    if isinstance(key,ast.Constant) and isinstance(key.value,str):
     k=key.value;defs[k]={'expression':ast.unparse(value),'locals':assignments,'line':func.lineno,'function':func.name};groups[k]=func.name.removeprefix('extract_').removesuffix('_features').upper()
vfunc=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='extract_structural_signals')
vassign={t.id:ast.unparse(n.value) for n in ast.walk(vfunc) if isinstance(n,ast.Assign) for t in n.targets if isinstance(t,ast.Name)}
vreturn=next(n for n in ast.walk(vfunc) if isinstance(n,ast.Return));exprs=vreturn.value.args[0].elts
ledger=[]
for model,names in [('V2',names2),('V4.3',names43)]:
 for i,name in enumerate(names):
  dd=defs[name] if model=='V2' else {'expression':ast.unparse(exprs[i]),'locals':vassign,'line':vfunc.lineno,'function':'extract_structural_signals'}
  # Exact return expression plus transitive local assignments, preserving regex names.
  needed=set(re.findall(r'\b[A-Za-z_]\w*\b',dd['expression']));pending=list(needed);selected={}
  while pending:
   x=pending.pop()
   if x in dd['locals'] and x not in selected:
    selected[x]=dd['locals'][x];pending.extend(re.findall(r'\b[A-Za-z_]\w*\b',selected[x]))
  expression=dd['expression']+'; '+ '; '.join(k+'='+v for k,v in selected.items())
  refs={k:v for k,v in regex.items() if k in expression}
  grp=groups[name] if model=='V2' else 'STRUCTURAL'
  depends='sender-dependent; missing => UNKNOWN, all sender indicators 0' if 'sender' in name else 'text-derived; formatting/domain/lexical style can proxy source or channel'
  ledger.append({'model':model,'index':i,'name':name,'definition':expression,'group':grp,'channel_dependence':depends,'sender_missing_share':'See sender_missing_by_file_label_source.csv; inference None for text-only','used_in':'model; Kotlin mirrored extractor','missing_value':'no regex match -> 0; denominators max(1,n); V2 None text -> empty; V4.3 requires string','regex_dependence':json.dumps(refs),'Kotlin_cost_to_change':'small for existing formula/regex; medium if added dimension/order','source':str((M/('scripts/feature_extraction.py' if model=='V2' else 'messages_v4_3/models/candidate_d_v4_3.py')).relative_to(ROOT)),'line':dd['line']})
 for group,vec in [('WORD_TFIDF',loaded[model][0][2]),('CHAR_TFIDF',loaded[model][0][3])]:
  offset=len(names) if group=='WORD_TFIDF' else len(names)+len(loaded[model][0][2].vocabulary_)
  for token,index in sorted(vec.vocabulary_.items(),key=lambda t:t[1]):
   ledger.append({'model':model,'index':offset+index,'name':group+':'+token,'definition':f'token={token!r}; idf={vec.idf_[index]:.12g}; sublinear_tf={vec.sublinear_tf}; norm={vec.norm}; analyzer={vec.analyzer}; ngrams={vec.ngram_range}; lowercase={vec.lowercase}','group':group,'channel_dependence':'lexical/source/register proxy possible; no sender input','sender_missing_share':'not consumed','used_in':'model + Kotlin vectorizer','missing_value':'out-of-vocabulary token contributes zero','regex_dependence':str(vec.token_pattern) if group=='WORD_TFIDF' else 'char_wb whitespace word boundary padding','Kotlin_cost_to_change':'none for new train-only vocab/IDF within fixed dimensions/settings; medium for dimensionality change','source':'frozen vectorizer bundle; see inference_manifest.json','line':''})
csvwrite('FEATURE_LEDGER.csv',ledger);save('feature_regexes.json',regex);save('feature_definitions.json',defs)
# Header missingness in every discovered training corpus, grouped by original labels/source.
corpora=load(OUT/'corpus_audit_manifest.json')['sources'];stats=collections.defaultdict(lambda:collections.Counter());filecounts=[]
reader=ast.parse(small(OUT/'audit_freeze.py'));exec(compile(ast.Module(body=[n for n in reader.body if isinstance(n,ast.FunctionDef) and n.name=='json_objects'],type_ignores=[]),'readonly_json_stream','exec'))
for c in corpora:
 if c['role']!='training':continue
 p=ROOT/c['path'];n=0
 for r in (rows(p) if p.suffix in ('.csv','.jsonl') else json_objects(p)):
  if not isinstance(r,dict) or not any(isinstance(r.get(k),str) for k in ('text','raw_text','message')):continue
  label=r.get('security_label',r.get('label',r.get('expected','MISSING')));src=r.get('source',r.get('dataset_source',r.get('source_dataset','MISSING')))
  label=str(label);src=json.dumps(src,sort_keys=True) if isinstance(src,(dict,list)) else str(src);key=(c['path'],label,src);st=stats[key];st['n']+=1;n+=1
  header=r.get('sender_header');st['key_absent']+='sender_header' not in r;st['null_or_blank']+=header is None or not str(header).strip();st['nonempty']+=header is not None and bool(str(header).strip());st['suffix_P']+=bool(header and re.search(r'[-_]P$',str(header),re.I));st['suffix_G']+=bool(header and re.search(r'[-_]G$',str(header),re.I))
 filecounts.append({'path':c['path'],'sha256':sha(p),'rows':n})
csvwrite('sender_missing_by_file_label_source.csv',[{'file':k[0],'label':k[1],'source':k[2],**dict(v),'missing_share':v['null_or_blank']/v['n']} for k,v in sorted(stats.items())])
save('sender_training_files.json',filecounts)
headers=[None,'AD-HDFCBK-P','AD-HDFCBK-G','AD-HDFCBK-S','HDFCBK-P','9000000123']
save('sender_code_tests.json',[{'header':h,'parser':vars(parse_sender_header(h)),'features':{k:v for k,v in extract_message_features('bank KYC pending',h).items() if 'sender' in k}} for h in headers])
# Structural/lexical activation on exactly matched probe pairs, no labels or scores used as feature truth.
probe=list(rows(OUT/'frozen/probe_v2.csv'));lookup={r['id']:r for r in probe};paired=[r for r in probe if r['language']=='Hinglish' and r['english_twin_id']];activation=[]
for model,names in [('V2',names2),('V4.3',names43)]:
 hh=np.array([extract_feature_vector(r['text'],None,FeatureConfig()) if model=='V2' else extract_structural_signals(r['text']) for r in paired]);ee=np.array([extract_feature_vector(lookup[r['english_twin_id']]['text'],None,FeatureConfig()) if model=='V2' else extract_structural_signals(lookup[r['english_twin_id']]['text']) for r in paired])
 for i,name in enumerate(names):activation.append({'model':model,'feature':name,'paired_n':len(paired),'H_nonzero':int((hh[:,i]!=0).sum()),'E_nonzero':int((ee[:,i]!=0).sum()),'E_active_H_zero':int(((ee[:,i]!=0)&(hh[:,i]==0)).sum()),'H_active_E_zero':int(((hh[:,i]!=0)&(ee[:,i]==0)).sum()),'constant_H':bool(np.all(hh[:,i]==hh[0,i]))})
csvwrite('paired_feature_activation.csv',activation)
# Fixed stratified historical TEST subsample; permutation after scaling; never fits anything.
test=list(rows(M/'data/processed/test.jsonl'));lab={'BENIGN':0,'SPAM':1,'SUSPICIOUS_SPAM':1,'MALICIOUS':2};rng=random.Random(202610232);sample=[]
for cl in range(3):
 pool=[(i,r) for i,r in enumerate(test) if lab[r['security_label']]==cl];sample+=rng.sample(pool,min(200,len(pool)))
sample.sort();ss=[r for i,r in sample];yy=np.array([lab[r['security_label']] for r in ss]);save('permutation_sample.json',{'source_sha256':sha(M/'data/processed/test.jsonl'),'indices':[i for i,r in sample],'class_counts':{str(c):int((yy==c).sum()) for c in range(3)},'seeds':[202610233,202610234,202610235],'n_repeats':3,'labels':'historical corpus labels; not independently reviewed','source':'processed/test.jsonl','note':'old diagnostic TEST, not new untouched test or sealed exam'})
def metrics(dd):return {'malicious_recall':float((dd[yy==2]==2).mean()),'nonmalicious_false_alert':float((dd[yy!=2]==2).mean()),'balanced_accuracy':float(np.mean([(dd[yy==c]==c).mean() for c in range(3)]))}
importance=[];pbase=[]
for model,names in [('V2',names2),('V4.3',names43)]:
 b=loaded[model];X=matrix(b,ss);base=metrics(decision(b[0][0].predict_proba(X),b[1]));pbase.append({'model':model,'condition':'sender_None','n':len(ss),**base})
 todo=[(name,[i],'individual_structural') for i,name in enumerate(names)]
 todo += [('ALL_STRUCTURAL',list(range(len(names))),'group'),('WORD_TFIDF',list(range(len(names),len(names)+len(b[0][2].vocabulary_))),'group'),('CHAR_TFIDF',list(range(len(names)+len(b[0][2].vocabulary_),X.shape[1])),'group')]
 if model=='V2':todo += [(g,[i for i,n in enumerate(names) if groups[n]==g],'group') for g in sorted(set(groups[n] for n in names))]
 for feature,ix,scope in todo:
  for seed in (202610233,202610234,202610235):
   order=np.random.default_rng(seed).permutation(len(ss));xp=X.copy();xp[:,ix]=X[order][:,ix];mm=metrics(decision(b[0][0].predict_proba(xp),b[1]))
   importance.append({'model':model,'feature':feature,'scope':scope,'seed':seed,'n':len(ss),'columns':len(ix),'recall_drop':base['malicious_recall']-mm['malicious_recall'],'false_alert_increase':mm['nonmalicious_false_alert']-base['nonmalicious_false_alert'],'balanced_accuracy_drop':base['balanced_accuracy']-mm['balanced_accuracy']})
  print(model,'permuted',feature,flush=True)
csvwrite('permutation_importance.csv',importance);save('permutation_baseline.json',pbase)
sources=[M/'scripts'/n for n in ['feature_extraction.py','feature_config.py','text_normalization.py','sender_parser.py']]+[M/'messages_v4_3/models/candidate_d_v4_3.py']
kdir=ROOT/'sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/messages'
sources += [kdir/n for n in ['MessageFeatureExtractor.kt','MessageAdjudicator.kt','MessageScanner.kt','SenderParser.kt','TextNormalizer.kt','DualTfidfVectorizer.kt']]
sources += [ROOT/'sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/sender/SenderClassifier.kt']
save('feature_evidence.json',{'sources':{p.relative_to(ROOT).as_posix():sha(p) for p in sources},'ledger_rows':len(ledger),'structural_features':{'V2':len(names2),'V4.3':len(names43)},'training_files':len(filecounts),'permutation_runs':len(importance),'elapsed_seconds':time.time()-t0,'no_training':True,'threads':1,'Kotlin_executed':False})
print('feature analysis completed',len(ledger),'ledger entries',len(importance),'permutations',round(time.time()-t0,1),'seconds')
