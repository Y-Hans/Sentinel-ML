"""
Dataset validator and integrity checking module for Message ML.

Ensures strict compliance with schema, taxonomy, privacy conventions, and data contracts.
"""

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_SECURITY_LABELS = {"BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"}

VALID_PRIMARY_TYPES = {
    "OTP_AUTH",
    "BANKING_TRANSACTIONAL",
    "SERVICE_UPDATE",
    "PROMOTIONAL",
    "GOVERNMENT_INFO",
    "PERSONAL_P2P",
    "DELIVERY",
    "INSTITUTIONAL_ANNOUNCEMENT",
    "SCAM",
    "UNKNOWN",
}

VALID_THREAT_VECTORS = {
    "NONE",
    "OTP_DISCLOSURE_REQUEST",
    "CREDENTIAL_REQUEST",
    "BANK_KYC_SUSPENSION",
    "ELECTRICITY_DISCONNECTION_SCAM",
    "UPI_COLLECT_FRAUD",
    "PAYMENT_SCAM",
    "PART_TIME_JOB_SCAM",
    "APK_MALWARE_DROPPER",
    "LOTTERY_PRIZE_FRAUD",
    "TRAFFIC_CHALLAN_PHISHING",
    "DELIVERY_SCAM",
    "INVESTMENT_SCAM",
    "EXTORTION_HARASSMENT",
    "COMMERCIAL_SPAM",
    "OTHER",
    "PHISHING",
    "OTP_THEFT",
}

VALID_SENDER_TYPES = {
    "ALPHANUMERIC_HEADER",
    "PHONE_NUMBER",
    "SHORTCODE",
    "UNKNOWN",
}

VALID_SPLITS = {"TRAIN", "VALIDATION", "TEST", "BENCHMARK", "OOD", "UNASSIGNED"}


@dataclass
class ValidationIssue:
    line_number: int
    message_id: Optional[str]
    issue_type: str
    description: str


@dataclass
class DatasetValidationReport:
    total_records: int = 0
    valid_records: int = 0
    invalid_records: int = 0
    duplicate_id_count: int = 0
    security_label_counts: Dict[str, int] = field(default_factory=Counter)
    primary_type_counts: Dict[str, int] = field(default_factory=Counter)
    threat_vector_counts: Dict[str, int] = field(default_factory=Counter)
    sender_type_counts: Dict[str, int] = field(default_factory=Counter)
    split_counts: Dict[str, int] = field(default_factory=Counter)
    source_counts: Dict[str, int] = field(default_factory=Counter)
    missing_fields_counts: Dict[str, int] = field(default_factory=Counter)
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.invalid_records == 0 and self.duplicate_id_count == 0


def validate_message_record(
    record: Dict[str, Any], line_num: int = 1
) -> Tuple[bool, List[ValidationIssue]]:
    """
    Validates an individual message record dictionary.
    Returns (is_valid, list_of_issues).
    """
    issues: List[ValidationIssue] = []
    msg_id = record.get("message_id")

    # 1. Required core fields
    for required_field in ["message_id", "raw_text", "security_label", "source_id"]:
        if required_field not in record or record[required_field] is None:
            issues.append(
                ValidationIssue(
                    line_number=line_num,
                    message_id=str(msg_id) if msg_id else None,
                    issue_type="MISSING_REQUIRED_FIELD",
                    description=f"Field '{required_field}' is mandatory but missing.",
                )
            )

    if not isinstance(record.get("raw_text"), str) or len(record.get("raw_text", "").strip()) == 0:
        issues.append(
            ValidationIssue(
                line_number=line_num,
                message_id=str(msg_id) if msg_id else None,
                issue_type="EMPTY_RAW_TEXT",
                description="Field 'raw_text' must be a non-empty string.",
            )
        )

    # 2. Security label check
    sec_label = record.get("security_label")
    if sec_label and sec_label not in VALID_SECURITY_LABELS:
        issues.append(
            ValidationIssue(
                line_number=line_num,
                message_id=str(msg_id) if msg_id else None,
                issue_type="INVALID_SECURITY_LABEL",
                description=f"Invalid security_label '{sec_label}'. Allowed: {VALID_SECURITY_LABELS}",
            )
        )

    # 3. Primary type check
    prim_type = record.get("primary_type")
    if prim_type is not None and prim_type not in VALID_PRIMARY_TYPES:
        issues.append(
            ValidationIssue(
                line_number=line_num,
                message_id=str(msg_id) if msg_id else None,
                issue_type="INVALID_PRIMARY_TYPE",
                description=f"Invalid primary_type '{prim_type}'. Allowed: {VALID_PRIMARY_TYPES}",
            )
        )

    # 4. Threat vectors check
    threats = record.get("threat_vectors")
    if threats is not None:
        if not isinstance(threats, list):
            issues.append(
                ValidationIssue(
                    line_number=line_num,
                    message_id=str(msg_id) if msg_id else None,
                    issue_type="INVALID_THREAT_VECTORS_TYPE",
                    description="Field 'threat_vectors' must be a list of strings.",
                )
            )
        else:
            for t in threats:
                if t not in VALID_THREAT_VECTORS:
                    issues.append(
                        ValidationIssue(
                            line_number=line_num,
                            message_id=str(msg_id) if msg_id else None,
                            issue_type="INVALID_THREAT_VECTOR_ITEM",
                            description=f"Unrecognized threat vector item '{t}'.",
                        )
                    )

    # 5. Split check
    split_val = record.get("split")
    if split_val is not None and split_val not in VALID_SPLITS:
        issues.append(
            ValidationIssue(
                line_number=line_num,
                message_id=str(msg_id) if msg_id else None,
                issue_type="INVALID_SPLIT",
                description=f"Invalid split '{split_val}'. Allowed: {VALID_SPLITS}",
            )
        )

    return (len(issues) == 0, issues)


def validate_dataset_file(file_path: Path) -> DatasetValidationReport:
    """
    Validates a JSONL dataset file and aggregates dataset statistics and integrity issues.
    """
    report = DatasetValidationReport()
    seen_ids: Set[str] = set()

    if not file_path.exists():
        report.issues.append(
            ValidationIssue(
                line_number=0,
                message_id=None,
                issue_type="FILE_NOT_FOUND",
                description=f"File {file_path} does not exist.",
            )
        )
        return report

    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            report.total_records += 1
            try:
                record = json.loads(line_str)
            except json.JSONDecodeError as e:
                report.invalid_records += 1
                report.issues.append(
                    ValidationIssue(
                        line_number=idx,
                        message_id=None,
                        issue_type="JSON_DECODE_ERROR",
                        description=f"Malformed JSON on line {idx}: {str(e)}",
                    )
                )
                continue

            is_valid, record_issues = validate_message_record(record, line_num=idx)
            if not is_valid:
                report.invalid_records += 1
                report.issues.extend(record_issues)
            else:
                report.valid_records += 1

            # Check duplicate message_ids
            msg_id = record.get("message_id")
            if msg_id:
                if msg_id in seen_ids:
                    report.duplicate_id_count += 1
                    report.issues.append(
                        ValidationIssue(
                            line_number=idx,
                            message_id=msg_id,
                            issue_type="DUPLICATE_MESSAGE_ID",
                            description=f"Duplicate message_id '{msg_id}' detected.",
                        )
                    )
                else:
                    seen_ids.add(msg_id)

            # Record stats
            report.security_label_counts[record.get("security_label", "MISSING")] += 1
            report.primary_type_counts[record.get("primary_type", "UNASSIGNED")] += 1
            report.sender_type_counts[record.get("sender_type", "UNASSIGNED")] += 1
            report.split_counts[record.get("split", "UNASSIGNED")] += 1
            report.source_counts[record.get("source_id", "MISSING")] += 1

            for threat in record.get("threat_vectors", []):
                report.threat_vector_counts[threat] += 1

            for optional_field in [
                "primary_type",
                "threat_vectors",
                "sender_header",
                "sender_type",
                "language",
                "script",
                "cleaned_text",
                "template_cluster_id",
            ]:
                if optional_field not in record or record[optional_field] is None:
                    report.missing_fields_counts[optional_field] += 1

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        rep = validate_dataset_file(target)
        print(f"Validation Report for: {target}")
        print(f"Total: {rep.total_records} | Valid: {rep.valid_records} | Invalid: {rep.invalid_records}")
        print(f"Duplicate IDs: {rep.duplicate_id_count}")
        print(f"Labels: {dict(rep.security_label_counts)}")
        print(f"Is Valid: {rep.is_valid}")
        if rep.issues:
            print(f"First {min(5, len(rep.issues))} issues:")
            for iss in rep.issues[:5]:
                print(f"  Line {iss.line_number}: [{iss.issue_type}] {iss.description}")
    else:
        print("Usage: python dataset_validator.py <path_to_jsonl>")
