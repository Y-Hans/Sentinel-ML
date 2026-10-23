"""
Template clustering, group-aware dataset splitting, and leakage analysis for Message ML.

Guarantees that parameter variations of the same SMS template cannot leak across
Train, Validation, Test, and Out-of-Distribution (OOD) partitions.
"""

from collections import defaultdict
from dataclasses import dataclass, field
import hashlib
import json
import random
from typing import Any, Dict, List, Set, Tuple

from text_normalization import analyze_and_normalize, mask_sensitive_patterns


def compute_template_cluster_id(text: str) -> str:
    """
    Computes a deterministic template cluster ID by abstracting numbers,
    amounts, dates, OTPs, phone numbers, accounts, and URLs into structural tokens.
    """
    if not text:
        return "CLUSTER_EMPTY"

    norm_res = analyze_and_normalize(text)
    masked = mask_sensitive_patterns(norm_res.normalized_lowercase)

    # Normalize multiple whitespace
    skeleton = " ".join(masked.split())

    # Generate 16-character deterministic hash prefix
    cluster_hash = hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16]
    return f"TMPL_{cluster_hash}"


@dataclass
class LeakageAuditReport:
    total_records: int = 0
    split_sizes: Dict[str, int] = field(default_factory=dict)
    exact_text_cross_split_overlaps: int = 0
    template_cluster_cross_split_overlaps: int = 0
    ood_sender_cross_split_overlaps: int = 0
    overlapping_templates: List[str] = field(default_factory=list)
    is_leakage_free: bool = True


def audit_splits_for_leakage(
    records_by_split: Dict[str, List[Dict[str, Any]]],
    check_ood_sender: bool = True,
) -> LeakageAuditReport:
    """
    Audits a partitioned dataset across all splits to verify zero cross-split
    exact text overlap and zero template cluster leakage.
    """
    report = LeakageAuditReport()
    split_texts: Dict[str, Set[str]] = defaultdict(set)
    split_templates: Dict[str, Set[str]] = defaultdict(set)
    split_senders: Dict[str, Set[str]] = defaultdict(set)

    total_recs = 0
    for split_name, recs in records_by_split.items():
        report.split_sizes[split_name] = len(recs)
        total_recs += len(recs)
        for r in recs:
            raw = r.get("raw_text", "").strip()
            tmpl_id = r.get("template_cluster_id") or compute_template_cluster_id(raw)
            sender = r.get("sender_header") or "UNKNOWN"

            split_texts[split_name].add(raw)
            split_templates[split_name].add(tmpl_id)
            split_senders[split_name].add(sender)

    report.total_records = total_recs

    # Check pairwise split overlaps
    splits = list(records_by_split.keys())
    for i in range(len(splits)):
        for j in range(i + 1, len(splits)):
            s1, s2 = splits[i], splits[j]

            # 1. Exact text overlap
            text_overlap = split_texts[s1].intersection(split_texts[s2])
            if text_overlap:
                report.exact_text_cross_split_overlaps += len(text_overlap)
                report.is_leakage_free = False

            # 2. Template cluster overlap
            tmpl_overlap = split_templates[s1].intersection(split_templates[s2])
            if tmpl_overlap:
                report.template_cluster_cross_split_overlaps += len(tmpl_overlap)
                report.overlapping_templates.extend(list(tmpl_overlap))
                report.is_leakage_free = False

            # 3. OOD sender overlap check (if evaluating OOD split against Train)
            if check_ood_sender and ("OOD" in (s1, s2)):
                non_ood = s1 if s2 == "OOD" else s2
                sender_overlap = split_senders["OOD"].intersection(split_senders[non_ood])
                # Exclude UNKNOWN from sender overlap penalty
                real_sender_overlap = {s for s in sender_overlap if s and s != "UNKNOWN"}
                if real_sender_overlap:
                    report.ood_sender_cross_split_overlaps += len(real_sender_overlap)

    return report


def partition_dataset_group_aware(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    ood_ratio: float = 0.0,
    seed: int = 42,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Partitions records into TRAIN, VALIDATION, TEST (and optionally OOD) splits
    grouped strictly by template_cluster_id to ensure zero template leakage.
    """
    total_ratio = train_ratio + val_ratio + test_ratio + ood_ratio
    if abs(total_ratio - 1.0) > 1e-5:
        raise ValueError(f"Split ratios must sum to 1.0, got {total_ratio:.4f}")

    # Group records by template_cluster_id
    clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        tmpl_id = r.get("template_cluster_id")
        if not tmpl_id:
            tmpl_id = compute_template_cluster_id(r.get("raw_text", ""))
            r["template_cluster_id"] = tmpl_id
        clusters[tmpl_id].append(r)

    # Sort cluster keys for deterministic shuffling
    cluster_ids = sorted(list(clusters.keys()))
    rng = random.Random(seed)
    rng.shuffle(cluster_ids)

    # Count items per cluster to balance partitions
    total_samples = len(records)
    target_train = int(total_samples * train_ratio)
    target_val = int(total_samples * val_ratio)
    target_test = int(total_samples * test_ratio)

    splits: Dict[str, List[Dict[str, Any]]] = {
        "TRAIN": [],
        "VALIDATION": [],
        "TEST": [],
    }
    if ood_ratio > 0.0:
        splits["OOD"] = []

    train_count = 0
    val_count = 0
    test_count = 0

    for cid in cluster_ids:
        group_records = clusters[cid]
        g_len = len(group_records)

        if train_count + g_len <= target_train or (val_count >= target_val and test_count >= target_test):
            for rec in group_records:
                rec["split"] = "TRAIN"
                splits["TRAIN"].append(rec)
            train_count += g_len
        elif val_count + g_len <= target_val or (test_count >= target_test):
            for rec in group_records:
                rec["split"] = "VALIDATION"
                splits["VALIDATION"].append(rec)
            val_count += g_len
        elif ood_ratio > 0.0 and len(splits["OOD"]) < int(total_samples * ood_ratio):
            for rec in group_records:
                rec["split"] = "OOD"
                splits["OOD"].append(rec)
        else:
            for rec in group_records:
                rec["split"] = "TEST"
                splits["TEST"].append(rec)
            test_count += g_len

    return splits
