# From-scratch URL data and fit plan — APPROVAL REQUIRED
No training has occurred. Keep HistGradientBoostingClassifier and exactly the current 67 features in alphabetical order; fresh weights, warm_start=False. Feature extraction and the Kotlin contract stay frozen. The model cannot learn domain reputation or page content absent from its features. New composition is a falsifiable experiment, not a promise that these features can separate all apex threats.

OBSERVED streaming inventory (not a complete historical fit manifest):

| Data file | BENIGN | ATTACK | Approx. unique registrable domains | Cross-class domains | Domain duplicate excess rows |
|---|---|---|---|---|---|
| cleaned_dataset.csv | 134850 | 100945 | 175355 | 272 | 60440 |
| data.csv | 134850 | 100945 | 175355 | 272 | 60440 |
| final_dataset.csv | 136807 | 101361 | 176010 | 275 | 62158 |
| v7_structural_benign.csv | 48290 | 0 | 15049 | 0 | 33241 |
| hard_dataset.csv | 1959 | 841 | 688 | 0 | 2112 |
| remediation_hard_negatives_v1.csv | 980 | 0 | 48 | 0 | 932 |
| remediation_hard_negatives_v2.csv | 2450 | 0 | 48 | 0 | 2402 |
| remediation_hard_negatives_v3.csv | 3430 | 0 | 48 | 0 | 3382 |
| v6_synthetic_benign.csv | 400 | 0 | 20 | 0 | 380 |

Cleaned-data source/form skew:

| Class | Dimension | Value | Rows |
|---|---|---|---|
| ATTACK | host_mix | apex | 21342 |
| ATTACK | host_mix | other_subdomain | 37859 |
| ATTACK | host_mix | www | 41744 |
| ATTACK | path_shape | deep_path | 7785 |
| ATTACK | path_shape | empty_path | 73489 |
| ATTACK | path_shape | short_path | 19671 |
| ATTACK | query_shape | no_query | 94866 |
| ATTACK | query_shape | path_query | 5046 |
| ATTACK | query_shape | root_query | 1033 |
| ATTACK | scheme_form | http | 51749 |
| ATTACK | scheme_form | https | 49196 |
| BENIGN | host_mix | www | 134850 |
| BENIGN | path_shape | empty_path | 134850 |
| BENIGN | query_shape | no_query | 134850 |
| BENIGN | scheme_form | https | 134850 |

All per-file source counts, domain concentration, exact URL duplicates, conflicts, path/query forms and hashes are in data_composition.json and the source/shape CSVs. cleaned_dataset.csv lacks source-family provenance, and data.csv mirrors its original source; final_dataset.csv has DatasetSource. Do not sum these overlapping files as independent evidence. Label mapping is recorded per file; original/cleaned 1 means benign and must be inverted. The counters use V8's short suffix table and are approximate for unlisted public/private suffixes. Domain mix (apex/www/subdomain) is separate from empty-path shape. Cross-class domains are plausible shared platforms; preserve and review them, not majority-vote them benign. Historical V8 export wraps the V7 base model; a row-level fit manifest is still missing.

Data program (user supplies offline files; no downloads/resolution/fetches in this sprint):
1. Supply deidentified navigation exports with URL, capture date, source family, label basis and review status. Sample actual bare roots, www roots, mobile/deep navigation, search/root queries, Indian regional/government/utility/bank/rail portals, software pages, shorteners and tenant links. Strip secrets consistently and record the transform; do not use altered syntax as labels. A known domain, rank or nonalerting model score does not establish endpoint truth.
2. Supply dated independently reviewed attack URLs with case/evidence IDs from internal confirmed incidents or user-obtained offline feeds. Include benign-looking malicious apexes with no credential tokens, same-brand lookalikes, new tenants, encoded payloads, open redirects, raw IP and IDN; evidence must support malicious destination/content when lexical syntax alone cannot. Keep conflicting labels/evidence as quarantined disputes. Record source date/hash and permission; model scores never supply labels.
3. Supply a dated offline full public suffix list including private suffixes and optional dated domains-only Tranco top-100k CSV. Hash before ingestion. Grouping can improve independently of the unchanged feature extractor. No suffix/rank update is silently inserted into the 67 features. Rank is sampling metadata and policy prior only.
4. Rebuild the pool from independent source families rather than append 15,000 benign roots. Desired minimum reviewed counts before fitting: 10,000 benign roots across >=5,000 parents; 10,000 evidence-backed low-signal apex attacks across >=5,000 parents; >=2,000 examples in each critical benign path/query/tenant family and attack payload/redirect/credential/IDN family where evidence allows. Cap rows per parent/source family (initial maximum 20, except separately documented platform holdouts) and cap near-duplicate templates at three. These minimums are provisional supply goals; if unmet, revise the registration for user review before any fit.
5. Join on canonical URL, normalized percent-decoding signatures and parent group; deduplicate within source and across sources before split. Audit cross-class exact URL conflicts, time validity and common template campaigns; quarantine conflicts. Never relabel all apexes from one source safe or all free tenants bad. A/B source families must both contribute path/query/host forms; report joint class x source x parent-shape x path/query cells and enforce minimum support.
6. Freeze new 70/15/15 parent-disjoint train/validation/test splits with a stable salted hash assignment and temporal/source audit. Use offline PSL registrable domains including private suffixes; all canonical variants and rows for a parent stay in one split. Ordinary github.com/docs.google.com share their registrable parent and stay together, even if that prevents platform-specific coverage in every split. Use an additional separate platform holdout report; do not break domain disjointness to populate cells. Existing clean test, this probe, the 500 and golden are now diagnostic/burned exclusions from new training/validation/test; exclude their parent groups from the new fitting pool. User-held exam remains unseen, including its URLs/domains; the user checks overlap privately and withholds conflicting rows without exposing exam identities.
7. The user holds a NEW untouched exam of >=2,000 benign +1,000 independently verified attacks, sampled from later dates and independent sources with joint attributes and >=100 low-signal malicious roots. The user authors/collects and labels it privately; neither this authored probe nor its review sample qualifies. One final candidate is submitted for a single evaluation. Pre-register the exam gates on supplied baseline denominators before the user unseals results. Do not create or inspect the exam here.

Avoiding Track A / S2-E: compose the whole dataset across source/parent/shape rather than add a big benign-root tranche or counter it with one malicious-root tranche. Preserve heterogeneous low-signal apex attacks, cap domain/source duplication, hold parents out, and evaluate apex recall separately. Validation uses worst-slice constraints and paired newly missed attacks, so gains on obvious hosted phishing cannot mask apex losses. Freeze data manifests before fitting and inspect feature collisions among disputed opposite-label examples; indistinguishable 67-feature examples define an accuracy limit. If that limit blocks gates, reject and propose features separately with Kotlin cost. Do not add the rejected B1 dictionary or rerun threshold-only apex rules.

Fit budget and selection: at most 8 fresh CPU fits and at most 4 aggregate CPU-hours, whichever comes first, one numerical thread (or <=floor(physical cores/4) after remeasurement), no GPU, installs or network. Stop workers before crossing the CPU budget using a supervisor that sums worker user+system CPU time. Reserve 15 minutes for final inference; no individual fit gets >25 CPU-minutes. Timeouts count toward the eight attempts; no hidden refits. Use 2 pre-hashed full-pool compositions (parent-capped equal source-family sampling; inverse-parent/source weights capped 3:1) x 2 conservative HGB parameter choices x 2 fixed seeds (42,20261023). Both compositions must meet the same reviewed cell minimums; these are not simple balanced-apex additions. Parameters: learning_rate=.06, max_iter=300, max_leaf_nodes in (31,40), min_samples_leaf=30, l2_regularization=5, early_stopping=False, warm_start=False, otherwise explicit defaults frozen with sklearn 1.9.0. Weights are fit-only. Use external domain-disjoint validation, never HGB random-row internal validation. No test, probe or burned set chooses composition/parameters/threshold.

Choose a global threshold using validation only: scan its unique raw probabilities and 0/1 boundaries; execute the frozen URL adjudicator at each candidate threshold without changing rule constants. Filter candidates by validation benign FPR <=1%, attack recall >=98.405%, and apex/low-signal recall within 0.2 percentage points of frozen V8 on the same validation. Prefer maximum minimum critical-slice recall, then lowest FPR, then fewer leaves, then earlier seed. Reject if no feasible threshold. Choose exactly one final model by validation criteria, freeze it and its threshold, and report the new domain-disjoint test, clean legacy test, current probe, red-team, 174 golden and 500 once. No revision or alternate candidate selection after these final reports. The safe-domain-prior prototype failed gates and is not bundled by default; any revised policy needs a fresh registration and unseen holdout. Any final report failure rejects promotion. Runtime export/Kotlin integration is a later separately approved task.

Final acceptance gates derived from the observed V8 URL adjudication baseline: at least 20% fewer probe benign false alerts (<=309/600 versus 387/600), no >0.2 percentage-point attack recall loss on clean test (>=22,789/23,158; baseline 22,835), no >0.2-point V8-normalized apex loss (>=4,162/4,254; baseline 4,170), <=46 newly missed clean attacks and <=8 newly missed apex attacks (paired, even if other recoveries offset them), clean FPR <=1.0% (<=273/27,353), probe attack recall no more than 0.2-point loss (requires 300/300 with this N), zero bypass/discount on payload/redirect/credential red-team cases, zero golden fixture regressions and no increase/new false alerts on burned 500. All class/slice N<30 results remain indicative. New domain-disjoint test must also satisfy validation numeric gates and critical-slice recall constraints against V8 on that same test. User-held exam gates must be frozen before its baseline scores are disclosed; target >=20% benign FP reduction and <=0.2-point recall loss, same hard-invariant zero bypass. Report uncertainty and all failures; do not tune from them.

The golden contract can call legitimate roots MALICIOUS. Correcting those predictions conflicts with strict zero fixture regression. Do not call fixture outputs threat truth, alter fixtures, waive gates, or overfit to fixture rows. Any requested semantic-fixture migration requires an explicit separate review by the user. A fit may be scientifically useful and still fail the sprint's promotion gates.

Two-day schedule after approval and data delivery: day 1 ingestion/provenance/conflict review/group split (CPU budget mostly untouched), freeze pool manifest; day 2 <=8 fits inside <=4 aggregate CPU-hours, validation selection, one final report and stop. If source evidence or private exam is missing, data work may continue but fitting/promotion remains gated. No training before the exact user reply APPROVED; approval alone does not manufacture missing data evidence.
