"""
Security evaluation metrics and confidence interval calculations for Message ML.

Implements precision, recall, F1, exact FPR, and Wilson Score 95% confidence bounds.
"""

from dataclasses import dataclass
import math
from typing import Dict, List, Optional, Tuple


@dataclass
class ConfidenceInterval:
    lower_bound: float
    upper_bound: float
    point_estimate: float
    confidence_level: float = 0.95


def wilson_score_interval(
    successes: int, total_trials: int, confidence: float = 0.95
) -> ConfidenceInterval:
    """
    Computes exact Wilson Score interval for binomial proportions (e.g. FPR, Error Rate).
    Robust even for zero false positives (0/N).
    """
    if total_trials <= 0:
        return ConfidenceInterval(0.0, 0.0, 0.0, confidence)

    # z = 1.95996 for 95% confidence
    z = 1.95996 if abs(confidence - 0.95) < 0.01 else 2.57583  # 99% fallback

    p_hat = successes / total_trials
    denominator = 1.0 + (z * z) / total_trials
    center = (p_hat + (z * z) / (2.0 * total_trials)) / denominator

    variance_term = (p_hat * (1.0 - p_hat) / total_trials) + ((z * z) / (4.0 * total_trials * total_trials))
    margin = (z * math.sqrt(max(0.0, variance_term))) / denominator

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return ConfidenceInterval(
        lower_bound=lower,
        upper_bound=upper,
        point_estimate=p_hat,
        confidence_level=confidence,
    )


@dataclass
class BinarySecurityMetrics:
    total_samples: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    fpr: float
    fpr_confidence_interval: ConfidenceInterval


def calculate_binary_metrics(
    y_true_binary: List[int],
    y_pred_binary: List[int],
    confidence_level: float = 0.95,
) -> BinarySecurityMetrics:
    """
    Calculates detailed security metrics for binary detection (e.g. Malicious=1, Benign=0).
    """
    total = len(y_true_binary)
    if total != len(y_pred_binary):
        raise ValueError("y_true and y_pred lengths must match")

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for yt, yp in zip(y_true_binary, y_pred_binary):
        if yt == 1 and yp == 1:
            tp += 1
        elif yt == 0 and yp == 0:
            tn += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 1 and yp == 0:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    total_negatives = tn + fp
    fpr = fp / total_negatives if total_negatives > 0 else 0.0
    fpr_ci = wilson_score_interval(fp, total_negatives, confidence=confidence_level)

    return BinarySecurityMetrics(
        total_samples=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        fpr=fpr,
        fpr_confidence_interval=fpr_ci,
    )
