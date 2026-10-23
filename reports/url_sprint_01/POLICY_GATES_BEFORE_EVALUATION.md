# Policy gates frozen before inference
PROVISIONAL design, 2026-10-23. All gates conjunctive; report failure without editing policy or thresholds.

| Gate | Required |
|---|---|
| Probe benign false alerts | At least 20% relative reduction versus V8 URL adjudication, using provisional labels |
| Clean-test attack recall | Loss no greater than 0.2 percentage points versus V8 URL adjudication |
| Red-team payload/redirect/credential bypass | Exactly zero of 160 authored cases |
| 174 burned golden regression report | Zero correct-to-wrong changes against fixture labels; also report all label changes and frozen-output disagreements |
| 500 burned benign regression report | No increase in total false positives or newly introduced false positives |

The burned sets are regression reports only; no design/threshold selection or iteration from their outputs. Strict frozen-output agreement may conflict with intended benign correction; report that separately and do not waive it. No fitting. Policy cap is an absolute 0.25 probability decrement applied only to exact registered hosts and explicitly allowed low-risk page shapes, after invariants. Never interpret adjusted scores as calibrated probabilities. No tenant discount. No thresholds tuned here. Ranking absent: curated sets only, no fabricated popularity rank.
