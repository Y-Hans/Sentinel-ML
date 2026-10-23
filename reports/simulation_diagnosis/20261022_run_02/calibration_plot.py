from runlib import *
protect()
os.environ['MPLCONFIGDIR']=str(OUT/'matplotlib_config_new')
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    rows=readrows(OUT/'calibration_reliability.jsonl'); fig,axes=plt.subplots(1,2,figsize=(11,4.5),layout='constrained')
    for ax,track,models in [(axes[0],'messages',['Messages_V2','Messages_V4.3','Messages_V4.4_candidate_b_refined']),(axes[1],'urls',['URL_V7','URL_V8'])]:
        ax.plot([0,1],[0,1],color='gray',linestyle='--',linewidth=1)
        for r in rows:
            if r['track']==track and r['model'] in models and r['mode']=='adjudicated' and r['scope']=='all_labeled' and r['assumed_prior'] is None and r['bins']:
                ax.plot([b['confidence'] for b in r['bins']],[b['observed_positive_rate'] for b in r['bins']],marker='o',label=r['model'].replace('Messages_','').replace('candidate_b_refined','B')+' n='+str(r['n']))
        ax.set(xlim=(0,1),ylim=(0,1),xlabel='Model / decision score',ylabel='Positive fraction in bin',title=track.capitalize()+': unweighted labeled challenge')
        ax.legend(fontsize=8)
    fig.suptitle('PROVISIONAL reliability diagnostics — authored / unreviewed labels; not deployment calibration',fontsize=10)
    fig.savefig(OUT/'PROVISIONAL_CALIBRATION_CURVES.svg'); fig.savefig(OUT/'PROVISIONAL_CALIBRATION_CURVES.png',dpi=150); plt.close(fig)
    jsave('calibration_plot_evidence.json',{'status':'OBSERVED figure from frozen computed bins; PROVISIONAL labels','matplotlib':matplotlib.__version__,'input_sha256':sha(OUT/'calibration_reliability.jsonl'),'outputs':{n:sha(OUT/n) for n in ('PROVISIONAL_CALIBRATION_CURVES.svg','PROVISIONAL_CALIBRATION_CURVES.png')}})
    print('saved reliability curve SVG and PNG')
except ImportError as e:
    jsave('calibration_plot_evidence.json',{'status':'fallback to complete bin curves in calibration_reliability.jsonl','error':repr(e),'input_sha256':sha(OUT/'calibration_reliability.jsonl')}); print('plot dependency unavailable; binned curves retained')
