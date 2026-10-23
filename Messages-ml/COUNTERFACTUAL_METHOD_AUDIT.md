# Counterfactual Method Audit — Explicit-Intent Matrix

**REPRODUCED** by running frozen V4.3 over twenty manually authored pairs. This is analysis-only and not a benchmark, performance estimate, training data, or independent evidence. τ=.61 remained unchanged.

## Label contract and construction

BENIGN=use a verifiable official channel or protect secrets; MALICIOUS=unsolicited solicitation of secrets, personal payment routing, unsafe executable source, or remote interception of delivery/authentication codes. These intended labels describe this constructed scenario, not generic lexical rules.

Each pair keeps the surrounding scenario fixed and substitutes one action clause/property. Rationales state that property and intended security semantics.

Every pair keeps its message frame and domain fixed, changing one action clause/property. The rationale records the intended semantic distinction. A MALICIOUS intended label does not mean every similar lexical string is malicious in all real contexts.

## Pair-level scores

| ID | Domain | Changed property | Intended B / M | Predicted B / M | P(non-benign) B / M | Intended score order? | Rationale |
|---|---|---|---|---|---:|---|---|

| CF01 | bank OTP | OTP disclosure request | B / M | MALICIOUS / MALICIOUS | 0.889 / 0.955 | yes | A security warning that prohibits disclosure is benign; an unsolicited agent asks for the authentication secret. |

| CF02 | bank password | credential handling channel | B / M | MALICIOUS / MALICIOUS | 0.723 / 0.970 | yes | The only changed action routes authentication from the official app to disclosure by text. |

| CF03 | account recovery | recovery-code recipient | B / M | MALICIOUS / MALICIOUS | 0.830 / 0.969 | yes | A recovery code is used locally in official settings versus disclosed to a third party. |

| CF04 | electricity bill | payment destination | B / M | BENIGN / MALICIOUS | 0.148 / 0.792 | yes | Same bill and payment intent; only the destination changes from the provider channel to a personal UPI handle. |

| CF05 | electricity disconnection | response channel and coercive callback | B / M | MALICIOUS / MALICIOUS | 0.731 / 0.987 | yes | This probes an unsolicited callback instruction; the explicit disconnection pressure is part of the malicious action clause. |

| CF06 | parcel delivery code | OTP delivery timing and recipient | B / M | MALICIOUS / BENIGN | 0.657 / 0.496 | **no** | The code is released at handoff versus remotely before the package arrives. |

| CF07 | parcel fee | payment channel | B / M | BENIGN / MALICIOUS | 0.152 / 0.983 | yes | Same fee request; only the route changes from the official carrier app to an unsolicited short URL. |

| CF08 | campus account | credential action | B / M | BENIGN / MALICIOUS | 0.165 / 0.993 | yes | Same institutional pretext; one version uses the official portal, the other solicits a password by SMS. |

| CF09 | university tuition | payment destination | B / M | BENIGN / MALICIOUS | 0.258 / 0.905 | yes | Same tuition payment request; the payment destination changes to a personal handle. |

| CF10 | Microsoft sign-in | credential submission route | B / M | MALICIOUS / MALICIOUS | 0.948 / 0.953 | yes | A password change in account settings versus password disclosure in a reply. |

| CF11 | SIM replacement | secret disclosure request | B / M | MALICIOUS / MALICIOUS | 0.988 / 0.997 | yes | Same account event; malicious version asks the recipient to disclose a SIM security secret. |

| CF12 | toll payment | payment destination | B / M | BENIGN / MALICIOUS | 0.025 / 0.820 | yes | Same debt notice; only the payee changes from official app to personal UPI. |

| CF13 | tax refund | verification action | B / M | BENIGN / MALICIOUS | 0.307 / 0.990 | yes | Same refund status; malicious version solicits an OTP rather than directing the user to the official portal. |

| CF14 | card security | security response | B / M | MALICIOUS / MALICIOUS | 0.976 / 0.999 | yes | Same alert; protective self-service action versus disclosure of a banking secret. |

| CF15 | medical portal | code recipient | B / M | BENIGN / MALICIOUS | 0.287 / 0.991 | yes | Same one-time code; local use in official app versus disclosure to an unsolicited caller. |

| CF16 | job application | application action/payment route | B / M | BENIGN / MALICIOUS | 0.371 / 0.990 | yes | Same job opportunity; malicious version requires an advance payment to a personal handle. |

| CF17 | software update | software distribution source | B / M | BENIGN / MALICIOUS | 0.010 / 0.703 | yes | Same update; trusted app-store distribution versus direct sideloaded executable source. |

| CF18 | shopping reward | claim action | B / M | BENIGN / MALICIOUS | 0.570 / 0.922 | yes | Same reward pretext; benign in-app viewing versus disclosure of a payment-card secret. |

| CF19 | WhatsApp device linking | linking-code recipient | B / M | MALICIOUS / MALICIOUS | 0.942 / 0.997 | yes | Same code; user-initiated in-app use versus remote disclosure to an unsolicited contact. |

| CF20 | government benefit | verification action | B / M | BENIGN / MALICIOUS | 0.519 / 0.987 | yes | Same benefit status; official portal lookup versus credential/OTP solicitation. |


**REPRODUCED:** intended score ordering is correct on 19/20 pairs; exact intended labels at τ=.61 are correct on 11/20 complete pairs. A pair counts as exact only when benign text predicts BENIGN and malicious text predicts MALICIOUS. CF06 reverses score order (doorstep OTP BENIGN scores above remote pre-arrival OTP MALICIOUS). Several pairs order correctly but classify both texts MALICIOUS, showing ranking and operating-point decision are different.

## Method limits

- All texts and rationales were created for this analysis; there is no independent authorship or sample population.
- Wording, token frequency, and sometimes message length change as part of the one substituted action clause; this is not a strict one-token intervention.
- Intended ground truth is scenario-level and assumes an unsolicited contact where stated; actual sender/channel provenance is not represented to the model.
- This matrix measures model response, not real-world accuracy. It must not be added to training or represented as a held-out benchmark.
- Machine-readable pairs, rationales and all three probabilities: [COUNTERFACTUAL_METHOD_AUDIT.json](COUNTERFACTUAL_METHOD_AUDIT.json).
