# Sprint results at Stage4 stop

OBSERVED: Stage0B and Stage1 executed; Stage2 designed. Candidate training/evaluation Stage5–6 not executed. DATA_AUDIT is pending handoff, not certified intake. Full baseline findings and intervals: PROBE_V2_RESULTS.md. FEATURE_LEDGER covers6089 input entries and315 permutations. Reproduced V4.3 English-metadata TEST1506/1551 malicious,92/707 BENIGN+SPAM false alerts; full historical TEST1510/1556 and92/708. These differ from benign-only2/520 and must not be conflated.

PROVISIONAL: v2 labels unreviewed; CandidateA94.83% recall but61.4% combined false alerts; V4.3 82.33% and42.2%. Probe results are synthetic stress diagnostics, not deployment accuracy. V1 active-pattern exclusions include46 Hinglish attacks and25 English attacks; the user-reported71 covers both languages, not71 Hinglish attacks. A rule-pass rejection is not proof an attack lacks a cue.

| Gate | Status | Baseline or required bound |
| --- | --- | --- |
| G1 | PROPOSED / candidate NOT EVALUATED | >=1497/1551; current 1506/1551 |
| G2 | PROPOSED / candidate NOT EVALUATED | <=92/707 (13.013%) |
| G3 | PROPOSED / candidate NOT EVALUATED | Probe>=510/600; each50-row family>=35/50; public heldout separately |
| G4 | PROPOSED / candidate NOT EVALUATED | Probe<=25/500; current211/500 (42.2%) |
| G5 | PROPOSED / candidate NOT EVALUATED | English<=47/188; current90/188; probe<=25/100; current14/100 |
| G6 | PROPOSED / candidate NOT EVALUATED | V4.3 probe207/240=86.25% vs287/360=79.72% |
| G7 | PROPOSED / candidate NOT EVALUATED | 8,388,608 bytes across vocab/IDF/scaler/trees |
