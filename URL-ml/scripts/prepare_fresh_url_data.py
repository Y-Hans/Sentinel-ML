"""Deduplicate, group, quarantine, and split the fresh URL collection."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))

from fresh_url_schema import read_jsonl, sha256_text, write_jsonl  # noqa: E402
from v7_features import TWO_LABEL_SUFFIXES  # noqa: E402


PARTITIONS = ("train", "validation", "final_test")
PARTITION_FRACTIONS = {"train": 0.70, "validation": 0.15, "final_test": 0.15}


def registrable_domain(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if not host:
        return ""
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    count = 2 if suffix in TWO_LABEL_SUFFIXES else 1
    return ".".join(labels[-(count + 1) :])


def group_id(record: dict) -> str:
    domain = record["registrable_domain"]
    if domain:
        return f"domain:{domain}"
    return f"url:{hashlib.sha256(record['canonical_url'].encode()).hexdigest()[:20]}"


def stable_rank(value: str, seed: int) -> int:
    return int(hashlib.sha256(f"{seed}:{value}".encode()).hexdigest(), 16)


def assign_groups(groups: dict[str, list[dict]], seed: int) -> dict[str, str]:
    assignment: dict[str, str] = {}
    by_label: dict[str, list[tuple[str, list[dict]]]] = defaultdict(list)
    for group, rows in groups.items():
        labels = {record["label"] for record in rows}
        if len(labels) != 1:
            continue
        by_label[next(iter(labels))].append((group, rows))

    for label, label_groups in by_label.items():
        ordered = sorted(label_groups, key=lambda item: stable_rank(item[0], seed))
        if label == "BENIGN":
            large_groups = [item for item in ordered if len(item[1]) >= 100]
            small_groups = [item for item in ordered if len(item[1]) < 100]
            for group, _rows in large_groups:
                assignment[group] = "train"
            small_groups = sorted(small_groups, key=lambda item: stable_rank(item[0], seed + 1))
            validation_count = max(1, round(len(small_groups) * 0.55)) if small_groups else 0
            for index, (group, _rows) in enumerate(small_groups):
                assignment[group] = "validation" if index < validation_count else "final_test"
            continue
        total_rows = sum(len(rows) for _, rows in ordered)
        targets = {
            "train": round(total_rows * PARTITION_FRACTIONS["train"]),
            "validation": round(total_rows * PARTITION_FRACTIONS["validation"]),
        }
        assigned_rows = 0
        partition_index = 0
        for group, rows in ordered:
            size = len(rows)
            if partition_index == 0 and assigned_rows + size > targets["train"] and assigned_rows > 0:
                partition_index = 1
            if partition_index == 1 and assigned_rows + size > targets["train"] + targets["validation"] and assigned_rows > targets["train"]:
                partition_index = 2
            partition = PARTITIONS[partition_index]
            assignment[group] = partition
            assigned_rows += size
    return assignment


def stats(rows: list[dict]) -> dict:
    return {
        "row_count": len(rows),
        "class_counts": dict(Counter(row["label"] for row in rows)),
        "source_counts": dict(Counter(row["source_name"] for row in rows)),
        "category_counts": dict(
            Counter(
                category
                for row in rows
                for category in (row.get("threat_category") or [row.get("domain_category", "unknown")])
            )
        ),
        "domain_count": len({row["registrable_domain"] for row in rows}),
        "group_count": len({row["domain_group_id"] for row in rows}),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261024)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    raw_path = args.raw_dir / "fresh_url_records.jsonl"
    source_registry_path = args.raw_dir / "source_registry.json"
    raw_records = read_jsonl(raw_path)
    quarantine: list[dict] = []
    by_url: dict[str, dict] = {}

    for record in raw_records:
        if not record.get("syntax_valid") or not record.get("canonical_url"):
            record["quarantine_reason"] = "invalid_url_syntax"
            quarantine.append(record)
            continue
        key = record["canonical_url"]
        previous = by_url.get(key)
        if previous is None:
            by_url[key] = record
        else:
            labels = {previous["label"], record["label"]}
            previous["source_name"] = ";".join(sorted(set(previous["source_name"].split(";")) | {record["source_name"]}))
            previous["corroborating_sources"] = sorted(
                set(previous.get("corroborating_sources", []))
                | set(record.get("corroborating_sources", []))
                | {record["source_name"]}
            )
            if len(labels) > 1:
                previous["label"] = "UNKNOWN"
                previous["quarantine_reason"] = "conflicting_duplicate_labels"

    deduped = list(by_url.values())
    for record in deduped:
        record["registrable_domain"] = registrable_domain(record["canonical_url"])
        record["domain_group_id"] = group_id(record)
        record["campaign_group_id"] = record.get("campaign_group_id") or record["domain_group_id"]
        record["url_family_id"] = record["domain_group_id"]

    groups: dict[str, list[dict]] = defaultdict(list)
    for record in deduped:
        if record["label"] not in {"BENIGN", "MALICIOUS"}:
            record["quarantine_reason"] = record.get("quarantine_reason", "unknown_label")
            quarantine.append(record)
            continue
        groups[record["domain_group_id"]].append(record)

    conflicted_groups = []
    for group, rows in list(groups.items()):
        if len({row["label"] for row in rows}) > 1:
            conflicted_groups.append(group)
            for row in rows:
                row["label"] = "UNKNOWN"
                row["quarantine_reason"] = "mixed_labels_within_domain_group"
                quarantine.append(row)
            del groups[group]

    assignment = assign_groups(groups, args.seed)
    partition_rows: dict[str, list[dict]] = {partition: [] for partition in PARTITIONS}
    for group, rows in groups.items():
        partition = assignment[group]
        for row in rows:
            row["partition"] = partition
            partition_rows[partition].append(row)

    for partition, rows in partition_rows.items():
        rows.sort(key=lambda row: row["canonical_url"])
        write_jsonl(args.output_dir / f"{partition}.jsonl", rows)
    write_jsonl(args.output_dir / "unknown_quarantine.jsonl", quarantine)

    overlap_sets = {}
    for left in PARTITIONS:
        for right in PARTITIONS:
            if left >= right:
                continue
            left_urls = {row["canonical_url"] for row in partition_rows[left]}
            right_urls = {row["canonical_url"] for row in partition_rows[right]}
            left_domains = {row["domain_group_id"] for row in partition_rows[left]}
            right_domains = {row["domain_group_id"] for row in partition_rows[right]}
            overlap_sets[f"{left}__{right}"] = {
                "url_overlap_count": len(left_urls & right_urls),
                "domain_group_overlap_count": len(left_domains & right_domains),
            }

    final_test_text = "\n".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) for row in partition_rows["final_test"]
    ) + "\n"
    manifest = {
        "dataset_id": "sentinel_fresh_url_20261024",
        "schema_version": "fresh_url_record_v1",
        "seed": args.seed,
        "collection_timestamp_utc": json.loads(source_registry_path.read_text(encoding="utf-8")).get(
            "collection_timestamp_utc"
        ),
        "partition_rules": {
            "fractions": PARTITION_FRACTIONS,
            "group_key": "registrable_domain, campaign_group_id, source_cluster_id, url_family_id",
            "final_test_frozen": True,
        },
        "raw_record_count": len(raw_records),
        "deduplicated_record_count": len(deduped),
        "quarantined_record_count": len(quarantine),
        "conflicted_group_count": len(conflicted_groups),
        "partitions": {partition: stats(rows) for partition, rows in partition_rows.items()},
        "quarantine_reasons": dict(Counter(row.get("quarantine_reason", "unknown") for row in quarantine)),
        "cross_partition_overlap": overlap_sets,
        "final_test_sha256": sha256_text(final_test_text),
        "source_registry_sha256": hashlib.sha256(source_registry_path.read_bytes()).hexdigest(),
        "source_registry": str(source_registry_path),
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
