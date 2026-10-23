"""
Benchmark evaluation harness for slice-based security testing in Message ML.

Evaluates predictors and rule systems across specialized slices with exact FPR confidence bounds.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional

# Ensure scripts and evaluation modules are importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evaluation"))

from metrics import BinarySecurityMetrics, calculate_binary_metrics
from rules_engine import evaluate_rules, RuleSignal


@dataclass
class SliceEvaluationResult:
    slice_name: str
    sample_count: int
    source_type: str
    true_label_counts: Dict[str, int]
    predicted_label_counts: Dict[str, int]
    false_positives: int
    false_negatives: int
    fpr: float
    fpr_95_ci_upper: float
    recall: float
    precision: float
    rules_fired_summary: Dict[str, int]


@dataclass
class BenchmarkSuiteReport:
    total_slices_evaluated: int = 0
    total_samples: int = 0
    slice_results: Dict[str, SliceEvaluationResult] = field(default_factory=dict)
    summary_markdown: str = ""


def evaluate_slice(
    slice_file: Path,
    predictor_fn: Optional[Callable[[str, Optional[str]], str]] = None,
) -> SliceEvaluationResult:
    """
    Evaluates a single benchmark slice JSONL file.
    If predictor_fn is None, evaluates deterministic rules as baseline signal.
    """
    slice_name = slice_file.stem
    records: List[Dict[str, Any]] = []

    with open(slice_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line.strip()))

    sample_count = len(records)
    source_type = records[0].get("source_type", "UNKNOWN") if records else "UNKNOWN"

    true_counts: Dict[str, int] = {}
    pred_counts: Dict[str, int] = {}
    rules_fired: Dict[str, int] = {}

    y_true_binary: List[int] = []
    y_pred_binary: List[int] = []

    for r in records:
        raw_text = r.get("raw_text", "")
        sender = r.get("sender_header")
        true_label = r.get("security_label", "BENIGN")

        true_counts[true_label] = true_counts.get(true_label, 0) + 1

        # Evaluate rules
        signals = evaluate_rules(raw_text, sender)
        for s in signals:
            rules_fired[s.signal_type] = rules_fired.get(s.signal_type, 0) + 1

        # Prediction
        if predictor_fn is not None:
            pred_label = predictor_fn(raw_text, sender)
        else:
            # Baseline Rule-Assisted Heuristic
            has_critical = any(s.severity in ("HIGH", "CRITICAL") for s in signals)
            has_legit_warn = any(s.signal_type in ("LEGIT_OTP_WARNING", "LEGIT_DELIVERY_OTP") for s in signals)
            if has_critical and not has_legit_warn:
                pred_label = "MALICIOUS"
            else:
                pred_label = "BENIGN"

        pred_counts[pred_label] = pred_counts.get(pred_label, 0) + 1

        # Convert to binary for security metrics (Malicious=1, Non-Malicious=0)
        y_true_binary.append(1 if true_label == "MALICIOUS" else 0)
        y_pred_binary.append(1 if pred_label == "MALICIOUS" else 0)

    metrics = calculate_binary_metrics(y_true_binary, y_pred_binary)

    return SliceEvaluationResult(
        slice_name=slice_name,
        sample_count=sample_count,
        source_type=source_type,
        true_label_counts=true_counts,
        predicted_label_counts=pred_counts,
        false_positives=metrics.false_positives,
        false_negatives=metrics.false_negatives,
        fpr=metrics.fpr,
        fpr_95_ci_upper=metrics.fpr_confidence_interval.upper_bound,
        recall=metrics.recall,
        precision=metrics.precision,
        rules_fired_summary=rules_fired,
    )


def run_benchmark_suite(
    benchmark_dir: Path,
    predictor_fn: Optional[Callable[[str, Optional[str]], str]] = None,
) -> BenchmarkSuiteReport:
    """
    Executes evaluation across all .jsonl benchmark files in the target directory.
    """
    report = BenchmarkSuiteReport()
    slice_files = sorted(list(benchmark_dir.glob("*.jsonl")))

    md_lines = [
        "# Message ML Benchmark Evaluation Report",
        "",
        "> [!IMPORTANT]",
        "> **SYNTHETIC DEVELOPMENT FIXTURE NOTICE**:",
        "> Current benchmark records are synthetic development fixtures designed solely for pipeline verification and contract testing.",
        "> They do NOT represent real-world production traffic, and metrics reported below must NOT be interpreted as production model accuracy.",
        "> An observed 0% FPR on small synthetic sample slices (e.g. 0 FP / 3 samples) does NOT establish a 0% real-world FPR.",
        "> The 95% Wilson Score confidence interval upper bounds demonstrate the true statistical uncertainty for small sample sizes.",
        "> Real, vetted datasets must be acquired and evaluated in subsequent phases before making any production performance claims.",
        "",
        "| Slice Name | Samples | Source Type | FP | FN | FPR (%) | 95% CI Upper (%) | Recall (%) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for sf in slice_files:
        res = evaluate_slice(sf, predictor_fn=predictor_fn)
        report.slice_results[res.slice_name] = res
        report.total_slices_evaluated += 1
        report.total_samples += res.sample_count

        md_lines.append(
            f"| `{res.slice_name}` | {res.sample_count} | {res.source_type} | {res.false_positives} | "
            f"{res.false_negatives} | {res.fpr * 100:.2f}% | {res.fpr_95_ci_upper * 100:.2f}% | {res.recall * 100:.2f}% |"
        )

    report.summary_markdown = "\n".join(md_lines)
    return report


if __name__ == "__main__":
    bench_path = ROOT / "data" / "benchmarks"
    if len(sys.argv) > 1:
        bench_path = Path(sys.argv[1])

    suite_report = run_benchmark_suite(bench_path)
    print(suite_report.summary_markdown)
