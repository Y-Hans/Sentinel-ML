# V4.4 RC2 Global Regression Forensic

**Status**: FORENSIC AUDIT COMPLETE
**Candidate Under Review**: RC2-Exp3 (Frozen) vs V4.3, RC1, Exp1, Exp2.

This report addresses the direct consequences of the sequential, targeted corpus corrections made during RC2 (Exp1: Utility, Exp2: Greetings, Exp3: Institutional) on the global performance and internal distribution geometry of the Sentinel model.

## 1. Global Regression Findings: The Recall vs. Targeted Probe Tradeoff

The iterative RC2 corrections did **not** improve Sentinel globally. Instead, they actively traded primary production recall for targeted regression probe improvements.

Comparing RC1 to Exp3 on the primary benchmark (`test.jsonl`, 1556 malicious records), we observed a **net loss of 17 malicious records** (21 newly missed vs 4 newly caught).

### Failure Mechanism Breakdown (The 21 Missed Records)

Of the 21 primary test records correctly caught by RC1 but missed by Exp3:

1. **Threshold Creep ($N=3$)**
   Because Exp3's classification threshold climbed to $\tau=0.74$, previously well-detected malicious records dropped below the decision boundary and were predicted as BENIGN. 
   - *Example*: `-MY LINKT-: You still owe money for one toll travel...`
     - RC1 Prob: 0.671 (Caught at $\tau=0.63$)
     - Exp3 Prob: 0.291 (Missed at $\tau=0.74$)
   - *Example*: `hello` (malicious probe)
     - RC1 Prob: 0.868
     - Exp3 Prob: 0.508 (Missed at $\tau=0.74$)

2. **Class Confusion: Malicious $\to$ Suspicious Spam ($N=18$)**
   The injection of synthetic benign institutional/utility records into the training corpus shifted the model's calibration for the `SPAM` class. As a result, 18 distinctly malicious examples (phishing, gift cards, scams) are now predicted as `SUSPICIOUS_SPAM` rather than `MALICIOUS` because their malicious probability dropped below their spam probability, overriding the primary threshold logic.
   - *Example*: `You have just been given 50 Eur gift card to redeem click here`
     - RC1 prediction: MALICIOUS (Non-benign: 0.980)
     - Exp3 prediction: SUSPICIOUS_SPAM (Benign: 0.115, Spam: 0.618, Malicious: 0.266).

## 2. Threshold Creep & Score Distributions

The threshold for V4.3 was mathematically locked at the 98th percentile (`p98`) of validation benign scores to enforce an FPR $\le 2.0\%$. 
Throughout RC2, the benign `p98` steadily climbed as we forcefully flattened specific probes (like electricity and greetings) without changing the architecture.

| Model | Benign Validation `p98` | Strict 2.0% FPR Threshold ($\tau$) |
|-------|-------------------------|------------------------------------|
| V4.3 | $0.597$ | $0.610$ |
| RC1 | $0.624$ | $0.630$ |
| Exp1 | $0.669$ | $0.680$ |
| Exp2 | $0.706$ | $0.680$ |
| Exp3 | $0.732$ | $0.740$ |

**Explanation**: The 4,019-dimensional TF-IDF feature space lacks the capacity to accommodate heavy, contradictory lexical overlap. When forced to map benign banking warnings ("Never share OTP") and malicious institutional phishing ("Share OTP to activate") into the same space, the model compresses the margins. Overall benign confidence distributions shift upwards, forcing the decision boundary ($\tau$) from $0.61$ all the way to $0.74$.

## 3. Explicit Verification of RC2 Claims

1. **Greeting Penalty Calibrated? NO.**
   Bare "Hello" scores $0.7975$ in Exp3. While this is mathematically lower than $0.94$, it is still $> 0.74$. The issue is not solved, the threshold simply masked part of it.
2. **Institutional Recovery Successful? NO.**
   While predicted malicious probabilities for institutional lures increased (e.g., $0.47 \to 0.72$), the elevated threshold of $\tau=0.74$ means these records still fail to cross the decision boundary. The recovery is a numerical illusion neutralized by threshold creep.
3. **Utility Improvement is Generalized? NO.**
   The improvement in utility/electricity false positives is strictly a targeted regression-probe improvement. It did not improve global generalizability and actively contributed to class confusion and threshold elevation.
4. **Holdouts as OOD Evidence? NO.**
   The V4.4 holdouts were co-generated with the training corpus and share identical template roots. They are targeted verification probes, not independent out-of-distribution (OOD) tests.

## 4. Conclusion & Architecture Proposal

**The sequential RC2 corpus corrections did not fix the model; they over-constrained a fundamentally limited architecture.**
The TF-IDF + HistGradientBoosting architecture has reached its representational limit. It relies on superficial lexical intersections (e.g., presence of "account", "update", "OTP", "bank") and lacks the sequential attention required to distinguish between "We will never ask for your OTP" (Benign) and "Click here to verify your OTP" (Malicious).

### Recommendation: V4.5 Architecture Experiment
Stop adding examples to the V4.4 corpus. The evidence definitively points to architecture-level lexical ambiguity. 
We must propose a **V4.5 Architecture Experiment** replacing the TF-IDF vectorizer with a sequential embedding approach (e.g., fine-tuned BERT/DistilBERT or an LSTM/Transformer layer) capable of capturing syntactic context and negation, explicitly designed to disentangle overlapping vocabulary.
