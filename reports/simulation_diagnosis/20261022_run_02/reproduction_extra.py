from runlib import *
protect()
s=(OUT/'infer_urls.py').read_text(encoding='utf-8'); s=s[:s.index("if phase=='reproduction':")]; exec(compile(s,'infer_urls.py definitions','exec'))
data=pd.read_csv(U/'data/hard_dataset.csv'); tt=data.url.tolist(); yt=data.label.astype(int).to_numpy(); X,_=vectorize_v7(tt); results=[]
for name,m in models.items():
    raw=m.base_model.predict_proba(X)[:,1]; adj=m.predict_proba(X,urls=tt)[:,1] if name=='8' else m.predict_proba(X)[:,1]
    for mode,p in [('raw',raw),('adjudicated',adj)]:
        pred=p>=m.threshold; results.append({'model':'URL_V'+name,'mode':mode,'threshold':m.threshold,'n':len(yt),'benign_n':int((yt==0).sum()),'attack_n':int((yt==1).sum()),'FP':int(pred[yt==0].sum()),'TP':int(pred[yt==1].sum()),'FPR':float(pred[yt==0].mean()),'recall':float(pred[yt==1].mean())})
jsave('url_hard_reproduction.json',{'source':str((U/'data/hard_dataset.csv').relative_to(ROOT)),'sha256':sha(U/'data/hard_dataset.csv'),'environment':env,'results':results,'note':'historical hard_dataset, not frozen 500-URL hard-benign reference; reproduction only, not gate tuning'})
print(json.dumps(results,indent=2))
