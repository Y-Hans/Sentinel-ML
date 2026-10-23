# Overlap sensitivity and confusion

OBSERVED predictions / ASSUMED synthetic labels. Confusion rows=true BENIGN,SPAM,MALICIOUS; columns=predicted BENIGN,SPAM,MALICIOUS. Flagged rows are tagged, not deleted from frozen material. All base verdicts remain on the full v2.

| Model | Scope | AttackTP | AttackN | NonmaliciousFP | NonmaliciousN | 3-way confusion |
| --- | --- | --- | --- | --- | --- | --- |
| V2 | all | 453 | 600 | 302 | 500 | [[122, 14, 264], [56, 6, 38], [137, 10, 453]] |
| V2 | no_overlap | 453 | 600 | 279 | 462 | [[107, 14, 241], [56, 6, 38], [137, 10, 453]] |
| V4.3 | all | 494 | 600 | 211 | 500 | [[201, 2, 197], [86, 0, 14], [106, 0, 494]] |
| V4.3 | no_overlap | 494 | 600 | 196 | 462 | [[178, 2, 182], [86, 0, 14], [106, 0, 494]] |
| V4.4_candidate_a_corrected | all | 569 | 600 | 307 | 500 | [[120, 0, 280], [73, 0, 27], [31, 0, 569]] |
| V4.4_candidate_a_corrected | no_overlap | 569 | 600 | 288 | 462 | [[101, 0, 261], [73, 0, 27], [31, 0, 569]] |
| V4.4_candidate_b_refined | all | 504 | 600 | 251 | 500 | [[162, 0, 238], [87, 0, 13], [96, 0, 504]] |
| V4.4_candidate_b_refined | no_overlap | 504 | 600 | 236 | 462 | [[139, 0, 223], [87, 0, 13], [96, 0, 504]] |
| V4.4_candidate_c_balanced | all | 477 | 600 | 216 | 500 | [[197, 0, 203], [87, 0, 13], [123, 0, 477]] |
| V4.4_candidate_c_balanced | no_overlap | 477 | 600 | 203 | 462 | [[172, 0, 190], [87, 0, 13], [123, 0, 477]] |
| V4.4_rc2_experiment_1 | all | 431 | 600 | 179 | 500 | [[228, 0, 172], [93, 0, 7], [169, 0, 431]] |
| V4.4_rc2_experiment_1 | no_overlap | 431 | 600 | 173 | 462 | [[196, 0, 166], [93, 0, 7], [169, 0, 431]] |
| V4.4_rc2_experiment_2 | all | 415 | 600 | 191 | 500 | [[217, 2, 181], [90, 0, 10], [185, 0, 415]] |
| V4.4_rc2_experiment_2 | no_overlap | 415 | 600 | 183 | 462 | [[187, 2, 173], [90, 0, 10], [185, 0, 415]] |
| V4.4_rc2_experiment_3 | all | 384 | 600 | 159 | 500 | [[248, 0, 152], [93, 0, 7], [216, 0, 384]] |
| V4.4_rc2_experiment_3 | no_overlap | 384 | 600 | 154 | 462 | [[215, 0, 147], [93, 0, 7], [216, 0, 384]] |

OBSERVED same-author prior blind-pass disagreements were46 Hinglish MALICIOUS +25 English MALICIOUS =71 across languages. Its labels are not independent ground truth. V1 active-pattern subset is selection-biased.

PROVISIONAL: neither high v2 recall nor low no-overlap FAR, if observed, demonstrates natural traffic performance. Shared phrasing and reserved-domain syntax remain limitations. Review frozen/REVIEW_SAMPLE_v2.csv before trust.
