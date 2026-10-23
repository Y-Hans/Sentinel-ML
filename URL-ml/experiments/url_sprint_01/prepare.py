from common import *
import random, re, ast, collections
from urllib.parse import urlsplit, unquote
from v7_features import canonicalize_url, V7_FEATURE_NAMES
snapshot('before')

# Burned corpora are accessed only by a blind URL-membership exclusion. No labels,
# scores, patterns, or performance from them influence generation or policy.
def urls_in(x):
    if isinstance(x,dict):
        for k,v in x.items():
            if k.lower()=='url' and isinstance(v,str): yield v
            elif isinstance(v,(dict,list)): yield from urls_in(v)
    elif isinstance(x,list):
        for v in x: yield from urls_in(v)
def key(u):
    p=urlsplit(canonicalize_url(u)); return (p.netloc.lower(), p.path.rstrip('/') if p.path in ('','/') else p.path,p.query,p.fragment)
burnpaths=[U/'data/hard_benign_benchmark_500.json',ROOT/'sentinel-ml/android-runtime/golden_test_data/golden_urls_v8.json']
burn=set(k for p in burnpaths for k in map(key,urls_in(json.loads(readtext(p)))))
seen=set(); rejected=collections.Counter(); probe=[]
def add(url,expected,form,category,platform,has_payload=0,tenant_hosted=0,variation_group='',variation_dimensions=''):
    k=key(url)
    # Keep raw-form variants deliberately, but remove exact/canonical reuse of burned URLs.
    if k in burn: rejected['burned_membership']+=1; return False
    if url in seen: rejected['duplicate']+=1; return False
    seen.add(url)
    probe.append(dict(id=f'P{len(probe)+1:04d}',url=url,expected=expected,form=form,category=category,platform=platform,has_payload=has_payload,tenant_hosted=tenant_hosted,source_note='PROVISIONAL: authored offline '+('ordinary navigation; endpoint existence/content unverified' if expected=='BENIGN' else 'adversarial scenario; registration and exploitability unverified'),variation_group=variation_group,variation_dimensions=variation_dimensions,label_status='PROVISIONAL'))
    return True
domains='''claude.ai instagram.com github.com google.com youtube.com bing.com duckduckgo.com python.org wikipedia.org mozilla.org npmjs.com pypi.org docker.com gitlab.com bitbucket.org stackoverflow.com cloudflare.com fastly.com digitalocean.com vercel.com netlify.com twitch.tv spotify.com netflix.com hulu.com disneyplus.com vimeo.com soundcloud.com dailymotion.com chess.com lichess.org roblox.com steampowered.com steamcommunity.com epicgames.com poki.com miniclip.com crazygames.com crazygames.io codenames.game chessigma.com arxiv.org kubernetes.io atlassian.com trello.com notion.so figma.com canva.com openai.com anthropic.com perplexity.ai groq.com huggingface.co kaggle.com colab.google zoom.us slack.com dropbox.com box.com proton.me fastmail.com icloud.com apple.com microsoft.com amazon.in flipkart.com myntra.com ajio.com meesho.com nykaa.com bigbasket.com blinkit.com zepto.com swiggy.com zomato.com irctc.co.in indianrail.gov.in railmadad.indianrailways.gov.in uidai.gov.in incometax.gov.in digilocker.gov.in india.gov.in mygov.in umang.gov.in epfindia.gov.in parivahan.gov.in passportindia.gov.in npci.org.in rbi.org.in sbi.co.in hdfcbank.com icicibank.com axisbank.com bankofbaroda.in canarabank.com pnbindia.in unionbankofindia.co.in indianbank.in idbibank.in kotak.com yesbank.in indusind.com federalbank.co.in southindianbank.com karurvysyabank.co.in cityunionbank.com tmb.in ucoBank.com bankofindia.co.in centralbankofindia.co.in mahadiscom.in bescom.co.in bsesdelhi.com tatapower.com adanielectricity.com iocl.com bharatpetroleum.in hindustanpetroleum.com indane.co.in airtel.in jio.com bsnl.co.in kerala.gov.in tamilnadu.gov.in karnataka.gov.in maharashtra.gov.in gujaratindia.gov.in odisha.gov.in wb.gov.in assam.gov.in rajasthan.gov.in up.gov.in bihar.gov.in telangana.gov.in ap.gov.in goa.gov.in haryana.gov.in punjab.gov.in uk.gov.in himachal.nic.in manipur.gov.in meghalaya.gov.in mizoram.gov.in nagaland.gov.in sikkim.gov.in tripura.gov.in arunachalpradesh.gov.in tn.gov.in thehindu.com indianexpress.com hindustantimes.com deccanherald.com onmanorama.com mathrubhumi.com manoramaonline.com dinamalar.com vikatan.com anandabazar.com eenadu.net sakshi.com prabhatkhabar.com jagran.com bhaskar.com lokmat.com esakal.com gujaratsamachar.com sandesh.com prajavani.net kannadaprabha.com orissapost.com assamtribune.com sentinelassam.com greaterkashmir.com tribuneindia.com dailypioneer.com theprint.in scroll.in newslaundry.com thewire.in livemint.com business-standard.com financialexpress.com outlookindia.com frontline.thehindu.com downToEarth.org.in indiaspend.com factly.in altnews.in boomlive.in thequint.com firstpost.com moneycontrol.com rediff.com ndtv.com abplive.com news18.com republicworld.com wionews.com dw.com france24.com aljazeera.com apnews.com reuters.com npr.org pbs.org cbc.ca abc.net.au rnz.co.nz rte.ie srf.ch svt.se yle.fi nrk.no dr.dk nos.nl rtve.es rtp.pt rai.it arte.tv euronews.com un.org who.int unesco.org unicef.org worldbank.org imf.org oecd.org wto.org isro.gov.in nasa.gov esa.int jaxa.jp cern.ch nist.gov noaa.gov usgs.gov nih.gov ncbi.nlm.nih.gov iitb.ac.in iitd.ac.in iitm.ac.in iitk.ac.in iisc.ac.in nptel.ac.in swayam.gov.in ignou.ac.in cbse.gov.in nta.ac.in ncert.nic.in du.ac.in jnu.ac.in bhu.ac.in jaduniv.edu.in amu.ac.in caluniv.ac.in mu.ac.in annauniv.edu coursera.org edx.org khanacademy.org brilliant.org duolingo.com memrise.com ankiweb.net gutenberg.org standardebooks.org openlibrary.org archive.org projecteuclid.org ams.org mathoverflow.net math.stackexchange.com superuser.com askubuntu.com serverfault.com unix.stackexchange.com opensuse.org ubuntu.com debian.org fedoraproject.org archlinux.org linuxmint.com freebsd.org openbsd.org netbsd.org raspberrypi.com kernel.org gnome.org kde.org libreoffice.org inkscape.org gimp.org blender.org audacityteam.org videolan.org obsproject.com 7-zip.org notepad-plus-plus.org code.visualstudio.com jetbrains.com eclipse.org apache.org sqlite.org postgresql.org mariadb.org redis.io rust-lang.org golang.org go.dev swift.org kotlinlang.org scala-lang.org julialang.org r-project.org cran.r-project.org rubygems.org ruby-lang.org php.net perl.org lua.org erlang.org elixir-lang.org haskell.org ocaml.org clojure.org racket-lang.org dlang.org ziglang.org nim-lang.org crystal-lang.org vlang.io deno.com bun.sh nodejs.org typescriptlang.org react.dev vuejs.org angular.dev svelte.dev astro.build nextjs.org nuxt.com remix.run vite.dev vitest.dev webpack.js.org rollupjs.org esbuild.github.io parceljs.org babeljs.io eslint.org prettier.io stylelint.io jestjs.io playwright.dev cypress.io selenium.dev beautifulsoup.readthedocs.io scrapy.org pandas.pydata.org numpy.org scipy.org scikit-learn.org matplotlib.org seaborn.pydata.org plotly.com bokeh.org altair-viz.github.io sympy.org jupyter.org ipython.org pydantic.dev fastapi.tiangolo.com flask.palletsprojects.com djangoproject.com sqlalchemy.org celeryq.dev streamlit.io gradio.app dash.plotly.com panel.holoviz.org holoviews.org hvplot.holoviz.org xarray.dev dask.org polars.rs duckdb.org ibis-project.org arrow.apache.org parquet.apache.org h5py.org pytables.org zarr.dev fsspec.github.io intake.readthedocs.io prefect.io dagster.io airflow.apache.org luigi.readthedocs.io mlflow.org wandb.ai neptune.ai comet.com clear.ml aimstack.io dvc.org lakefs.io pachyderm.com kedro.org zenml.io bentoml.com seldon.io kserve.github.io ray.io modal.com replicate.com together.ai fireworks.ai cerebras.ai sambanova.ai deepinfra.com baseten.co runpod.io vast.ai lambda.ai coreweave.com crusoe.ai'''.lower().split()
domains=list(dict.fromkeys(domains))
# 50 domain groups x four canonical forms. If a group is burned, discard it blindly.
root_groups=0
for d in domains:
    forms=[('https://'+d,'bare_apex'),('https://www.'+d,'www'),(d,'schemeless'),('//'+d,'protocol_relative')]
    if any(key(u) in burn for u,_ in forms): continue
    if root_groups==50: break
    for u,f in forms: add(u,'BENIGN',f,'ordinary_root',d,variation_group=d+'|root',variation_dimensions='scheme,www')
    root_groups+=1
assert root_groups==50,root_groups
# Explicit useful deep navigation: three identifiers per page shape, no shape >3.
templates=[
 ('claude.ai','/chat/{uuid}','chat',0),('github.com','/sentinel-sprint/guide-{i}','repository',1),
 ('github.com','/sentinel-sprint/guide-{i}/blob/main/README.md','source',1),('github.com','/sentinel-sprint/guide-{i}/issues/{n}','issue',1),
 ('docs.google.com','/document/d/{token}/edit','document',1),('docs.google.com','/spreadsheets/d/{token}/edit','spreadsheet',1),
 ('docs.google.com','/forms/d/e/{token}/viewform','form',1),('drive.google.com','/file/d/{token}/view','drive',1),
 ('youtube.com','/watch?v={yt}','watch',1),('youtube.com','/shorts/{yt}','shorts',1),('youtube.com','/@sentinellearning{i}/videos','channel',1),
 ('instagram.com','/reel/{token}/','reel',1),('instagram.com','/p/{token}/','post',1),
 ('gitlab.com','/sentinel-sprint/guide-{i}/-/tree/main','repository',1),('stackoverflow.com','/questions/{n}/offline-url-shapes','question',1),
 ('arxiv.org','/abs/2610.{n}','paper',0),('en.wikipedia.org','/wiki/{topic}','article',1),('docs.python.org','/3/library/{module}.html','documentation',0),
 ('play.google.com','/store/apps/details?id=org.sentinel.sprint{i}','app_store_page',1),('apps.apple.com','/in/app/sprint-notes/id{n}','app_store_page',1),
 ('python.org','/downloads/release/python-3{i}0/','software_page',0),('mozilla.org','/en-US/firefox/{section}/','software_page',0),
 ('bit.ly','/{token}','shortener',1),('t.co','/{token}','shortener',1),('tinyurl.com','/{token}','shortener',1),('youtu.be','/{yt}','shortener',1),
 ('forms.gle','/{token}','shortener',1),('aka.ms','/sprint-notes-{i}','shortener',1),('amzn.to','/{token}','shortener',1),
 ('drive.google.com','/drive/folders/{token}','drive',1),('notion.so','/Sprint-notes-{token}','document',1),('dropbox.com','/s/{token}/notes.pdf?dl=0','document',1),
 ('github.com','/sentinel-sprint/guide-{i}/commit/{hash}','commit',1),('github.com','/sentinel-sprint/guide-{i}/releases/tag/v1.0','release_page',1),
 ('microsoft.com','/en-in/download/details.aspx?id={n}','software_page',0),('support.apple.com','/en-in/{n}','support',0),
 ('ubuntu.com','/download/{section}','software_page',0),('videolan.org','/vlc/{section}.html','software_page',0),
 ('developer.android.com','/guide/topics/{topic}','documentation',0),('developer.mozilla.org','/en-US/docs/Web/{topic}','documentation',1),
 ]
for d,t,cat,tenant in templates:
    for i in range(3):
        token=hashlib.sha256(f'url-sprint:{d}:{t}:{i}'.encode()).hexdigest()[:24]
        vals=dict(i=i,n=846210+i,uuid=f'3b19a36e-82a4-4d6c-97ab-{token[:12]}',token=token,yt=token[:11],hash=token,topic=['Astronomy','Geometry','Ecology'][i],module=['pathlib','csv','datetime'][i],section=['desktop','features','privacy'][i])
        add('https://'+d+t.format(**vals),'BENIGN','deep_path',cat,d,tenant_hosted=tenant,variation_group=d+'|'+t,variation_dimensions='identifier or topic')
search_terms=['monsoon+forecast+kolkata','python+csv+reader','train+time+table','classical+music+india','local+library+hours','sprint+planning+notes','vegetable+recipes','astronomy+calendar','metro+route+map','regional+poetry','public+parks','language+learning','postal+code+guide','rural+health+centres','science+museum','water+conservation','university+courses','history+archives','book+reviews','cycling+trails']
for d in ('google.com','bing.com','duckduckgo.com'):
    for i,q in enumerate(search_terms):
        add('https://'+d+('/search?q=' if d!='duckduckgo.com' else '/?q=')+q+'&hl=en-IN','BENIGN','search' if d!='duckduckgo.com' else 'root_query','search',d,variation_group=d+'|search|'+str(i//3),variation_dimensions='query topic')
for d in ('google.com','bing.com'):
    for i,q in enumerate(search_terms[:10]): add('https://'+d+'/?q='+q+'&source=sprint01','BENIGN','root_query','root_query',d,variation_group=d+'|rootquery|'+str(i//3),variation_dimensions='query topic')
portals=[d for d in domains if any(x in d for x in ('.gov.in','.nic.in','bank','sbi.co.in','npci.org','rbi.org','irctc','rail','mahadiscom','bescom','bses','tatapower','adanielectricity','airtel.in','jio.com'))]
for d in portals:
    for path in ('/','/contact-us','/about-us'):
        add('https://'+d+path,'BENIGN','bare_apex' if path=='/' else 'deep_path','indian_portal',d,variation_group=d+'|portal',variation_dimensions='root,contact,about')
        if sum(r['expected']=='BENIGN' for r in probe)>=560: break
    if sum(r['expected']=='BENIGN' for r in probe)>=560: break
regional=[d for d in domains if d in domains[domains.index('thehindu.com'):domains.index('un.org')]]
for d in regional+domains:
    for path in ('/about','/contact','/privacy'):
        if sum(r['expected']=='BENIGN' for r in probe)>=600: break
        add('https://'+d+path,'BENIGN','deep_path','regional_navigation' if d in regional else 'ordinary_navigation',d,variation_group=d+'|navigation',variation_dimensions='about,contact,privacy')
    if sum(r['expected']=='BENIGN' for r in probe)>=600: break
assert len(probe)==600,len(probe)

# Long invented domains; no registration, DNS, blocklist, or content claims are made.
def invented(i):
    return 'auroravault-'+hashlib.sha256(f'sprint-attack-20261023-{i}'.encode()).hexdigest()[:22]+['.com','.net','.org','.co.in','.app'][i%5]
attack_categories=['lookalike','subdomain_trick','payload_unknown','payload_popular','open_redirect','raw_ip','tenant_phishing','punycode','encoded_nested','typosquat']
for i in range(300):
    cat=attack_categories[i%10]; h=invented(i); token=hashlib.sha256(h.encode()).hexdigest()[:16]; payload=0;tenant=0
    if cat=='lookalike': u=f'https://microsoft-{h}/signin/password?session={token}'
    elif cat=='subdomain_trick': u=f'https://accounts.google.com.{h}/verify/credential'
    elif cat=='payload_unknown': u=f'https://{h}/mobile/{token}'+('.apk' if i%20==2 else '.exe');payload=1
    elif cat=='payload_popular':
        host=['github.com','drive.google.com','dropbox.com','youtube.com','claude.ai','instagram.com'][i//10%6]
        u=f'https://{host}/sprint-{token}/installer'+('.apk' if i%20==3 else '.exe');payload=1;tenant=int(host in ('github.com','drive.google.com','dropbox.com'))
    elif cat=='open_redirect':
        host=['google.com','bing.com','youtube.com','github.com','claude.ai'][i//10%5]
        u=f'https://{host}/url?next=https%3A%2F%2F{h}%2Fsignin%3Fid%3D{token}'
    elif cat=='raw_ip': u=f'http://192.0.2.{1+i//10}/account/password?id={token}'
    elif cat=='tenant_phishing':
        tenant=1; suffix=['github.io','firebaseapp.com','pages.dev','blogspot.com','web.app','netlify.app'][i//10%6];u=f'https://sprint-{token}.{suffix}/account/credential'
    elif cat=='punycode': u=f'https://xn--pypal-{token}.com/signin/password'
    elif cat=='encoded_nested': u=f'https://{h}/go/%2570assword?target=https%253A%252F%252F{invented(900+i)}%252Fverify'
    else: u=f'https://g00gle-{h}/signin/otp'
    add(u,'ATTACK','raw_ip' if cat=='raw_ip' else 'encoded' if cat=='encoded_nested' else 'deep_path',cat,host if cat in ('payload_popular','open_redirect') else suffix if cat=='tenant_phishing' else 'invented',payload,tenant,cat+'|'+str(i),'host,path,encoding,target')
assert len(probe)==900
csvout(OUT/'probe.csv',probe)
rng=random.Random(20261023)
review=[dict(r,user_agree='',user_note='') for e in ('ATTACK','BENIGN') for r in rng.sample([r for r in probe if r['expected']==e],60)]
rng.shuffle(review);csvout(OUT/'REVIEW_SAMPLE.csv',review)

# Separate threat invariant stress set, >=100 cases, fixed before any inference.
red=[]
popular=['google.com','youtube.com','github.com','claude.ai','instagram.com','bing.com','python.org','mozilla.org','drive.google.com','docs.google.com']
tenants=['a-sprint.github.io','a-sprint.firebaseapp.com','a-sprint.pages.dev','a-sprint.blogspot.com','a-sprint.web.app','a-sprint.netlify.app','a-sprint.vercel.app','a-sprint.gitlab.io','docs.google.com','forms.google.com']
shapes=[('/chat/install.apk','payload'),('/releases/client.EXE?download=1','payload'),('/download?file=update%252Eapk','payload'),('/url?next=https%253A%252F%252F'+invented(1200)+'/password','redirect'),('/chat/redirect?return_to=//'+invented(1201),'redirect'),('/forms/d/e/sprint/viewform?entry.1=password','credential'),('/login/verify/credential','credential'),('/chat/%2570%2561ssword','credential')]
for h in popular+tenants:
    for path,kind in shapes:
        red.append(dict(id=f'R{len(red)+1:04d}',url='https://'+h+path,expected='ATTACK',kind=kind,tenant_hosted=int(h in tenants),label_status='PROVISIONAL'))
csvout(OUT/'red_team.csv',red)
tranco=list((U/'external/tranco').glob('*.csv')) if (U/'external/tranco').exists() else []
js(OUT/'freeze.json',{'time_utc':stamp(),'probe_sha256':sha(OUT/'probe.csv'),'red_team_sha256':sha(OUT/'red_team.csv'),'review_sha256':sha(OUT/'REVIEW_SAMPLE.csv'),'n':900,'class_counts':dict(collections.Counter(r['expected'] for r in probe)),'forms':dict(collections.Counter(r['form'] for r in probe)),'generation_seed':20261023,'root_groups':root_groups,'blind_exclusions':dict(rejected),'burned_membership_only_inputs':{str(p.relative_to(ROOT)):sha(p) for p in burnpaths},'tranco_candidates':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p),'bytes':p.stat().st_size} for p in tranco]})
write(OUT/'POLICY_GATES_BEFORE_EVALUATION.md','''# Policy gates frozen before inference
PROVISIONAL design, 2026-10-23. All gates conjunctive; report failure without editing policy or thresholds.

| Gate | Required |
|---|---|
| Probe benign false alerts | At least 20% relative reduction versus V8 URL adjudication, using provisional labels |
| Clean-test attack recall | Loss no greater than 0.2 percentage points versus V8 URL adjudication |
| Red-team payload/redirect/credential bypass | Exactly zero of 160 authored cases |
| 174 burned golden regression report | Zero correct-to-wrong changes against fixture labels; also report all label changes and frozen-output disagreements |
| 500 burned benign regression report | No increase in total false positives or newly introduced false positives |

The burned sets are regression reports only; no design/threshold selection or iteration from their outputs. Strict frozen-output agreement may conflict with intended benign correction; report that separately and do not waive it. No fitting. Policy cap is an absolute 0.25 probability decrement applied only to exact registered hosts and explicitly allowed low-risk page shapes, after invariants. Never interpret adjusted scores as calibrated probabilities. No tenant discount. No thresholds tuned here. Ranking absent: curated sets only, no fabricated popularity rank.
''')
write(OUT/'PROBE_DESIGN.md','''# Offline authored URL probe
PROVISIONAL expected labels, not observed threats or confirmed benign endpoints. 600 BENIGN and 300 ATTACK; 120 balanced random review rows; 160 separate red-team scenarios. Raw IPs use documentation range 192.0.2.0/24. All attacker-controlled domains are long deterministic invented brand-like strings with realistic TLD shapes. Registration/nonregistration cannot be established offline; none is knowingly registered and no blocklist was consulted. Paths, content, shortener destinations and open-redirect exploitability are unverified. Payload cases are policy hazards, not proof that software downloads are malware.

The first 200 rows are 50 roots with four explicit variations (https apex/www/schemeless/protocol-relative). Burned membership is excluded blindly, treating root trailing slash and scheme as equivalent. Schemeless and protocol-relative intentionally collapse under feature canonicalization. Other rows cover chat, repositories, documents/forms/Drive, reels/videos, search/root queries, Indian portals, stores/software pages, shorteners and regional navigation. Variation groups and dimensions are explicit; deep identifier templates capped at three. Search topics are grouped in triples. Correlated examples mean row-level Wilson intervals are descriptive; they overstate effective independent sample size. This is a stress probe, not a traffic prevalence survey. Counts and hashes are in freeze.json. Popular root membership may be constrained by burned exclusions. Shared parent/platform examples deliberately stress policy safety; do not infer endpoint immunity.

REVIEW_SAMPLE.csv: fill user_agree/user_note. If more than 5% of reviewed labels are wrong (>6 of 120), invalidate and regenerate the probe before further design decisions. Shortener and public-content benign labels particularly require review. Model scores never define labels. Neither this probe nor reviewed versions may become an untouched final exam.
''')
print('Frozen probe',sha(OUT/'probe.csv'),'red team',len(red),flush=True)
