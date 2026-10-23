"""
Deterministic rule and heuristic signal engine for Message ML.

Emits structured, auditable RuleSignals (not forced unconditional verdicts)
for contextual fusion in the Sentinel security decision layer.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional

from sender_parser import parse_sender_header, SenderParseResult
from text_normalization import analyze_and_normalize, TextNormalizationResult


@dataclass
class RuleSignal:
    rule_id: str
    signal_type: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    evidence: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Rule Heuristics
# ============================================================================

# 1. Reverse OTP Theft / Disclosure Request Pattern
RE_RULE_OTP_THEFT = re.compile(
    r"\b(?:share|send|tell|forward|provide|give|message)\s+(?:me\s+|us\s+|your\s+|the\s+)?(?:\d+\s*(?:digit|digits)?\s*)?(?:secret\s+)?(?:otp|code|pin|password|one\s*time\s*password)\b|"
    r"\b(?:otp|code|pin)\s+(?:to\s+(?:cancel|stop|verify|customer\s*care|support|executive|officer|manager|number))\b|"
    r"\b(?:forward|send)\s+this\s+(?:sms|message|otp)\s+to\b",
    re.IGNORECASE,
)

# 2. Legitimate OTP Warning Pattern
RE_RULE_OTP_LEGIT_WARNING = re.compile(
    r"\b(?:never\s+share|do\s+not\s+(?:share|disclose|give|tell|forward)|bank\s+never\s+asks|keep\s+(?:it\s+)?confidential|strictly\s+confidential|don'?t\s+share)\s+(?:this\s+|your\s+|the\s+)?(?:\d+\s*(?:digit|digits)?\s*)?(?:secret\s+)?(?:otp|code|password|pin|details|info)\b|"
    r"\b(?:uidai|bank|staff)\s+never\s+(?:calls?|asks?|requests?)\b|"
    r"\bnever\s+disclose\s+(?:otp|pin|password)\b",
    re.IGNORECASE,
)

# 3. Legitimate Delivery OTP Pattern
RE_RULE_DELIVERY_OTP = re.compile(
    r"\b(?:delivery\s+(?:agent|associate|partner|boy|executive|person)|courier|package|order|arriving)\b.*"
    r"\b(?:share|give|provide)\s+(?:delivery\s+)?(?:otp|code|pin)\b|"
    r"\b(?:delivery\s+otp)\s+(?:is\s+)?\d{4,8}\b",
    re.IGNORECASE,
)

# 4. Electricity Disconnection Scam Pattern (Cutoff + Phone Number CTA)
RE_RULE_ELECTRICITY_DISCONNECT = re.compile(
    r"\b(?:electricity|power|bijli|light\s+bill)\b.*"
    r"\b(?:disconnected|cut|suspended|stopped|tonight|due\s+bill|unpaid|kat\s+jayegi|jama)\b.*"
    r"(?:\+91|0)?[6-9]\d{9}|"
    r"(?:\+91|0)?[6-9]\d{9}.*\b(?:electricity|power|bijli)\b.*\b(?:disconnected|cut|suspended|kat\s+jayegi)\b",
    re.IGNORECASE,
)

# 5. Bank Account / KYC / PAN Suspension with Link
RE_RULE_BANK_KYC_LINK = re.compile(
    r"\b(?:sbi|yono|hdfc|icici|axis|pnb|kotak|bob|canara|bank\s*a/c|pan\s*card|kyc)\b.*"
    r"\b(?:blocked|suspended|deactivated|closed|restricted|pending|band|update|verify)\b.*"
    r"(?:https?://|www\.|bit\.ly|tinyurl|is\.gd|cutt\.ly|t\.co|shorturl)|"
    r"(?:https?://|www\.|bit\.ly|tinyurl|is\.gd|cutt\.ly|t\.co|shorturl).*"
    r"\b(?:sbi|yono|hdfc|icici|axis|pnb|kotak|bob|canara|bank\s*a/c|pan\s*card|kyc)\b.*"
    r"\b(?:blocked|suspended|deactivated|update|verify|band)\b",
    re.IGNORECASE,
)

# 6. APK Dropper Pattern
RE_RULE_APK_DROPPER = re.compile(
    r"(?:https?://\S+|www\.\S+|wa\.me/\S+).*\.apk\b|"
    r"\.apk\b.*(?:https?://\S+|www\.\S+|download)|"
    r"\b(?:download|install)\s+(?:support|bank|customercare|live)\s+app\b",
    re.IGNORECASE,
)

# 7. UPI Collect / Prize PIN Fraud
RE_RULE_UPI_COLLECT = re.compile(
    r"\b(?:lottery|won|cashback|reward|scratch\s*card)\b.*"
    r"\b(?:enter\s+(?:upi\s+)?pin|approve\s+collect|accept\s+request|send\s+pin)\b|"
    r"\b(?:enter\s+(?:upi\s+)?pin\s+to\s+receive\s+(?:money|cashback|prize|amount))\b",
    re.IGNORECASE,
)

# 8. Part-Time Review / Rating Scam (Job Task Lure + WhatsApp/Telegram)
RE_RULE_TASK_JOB_SCAM = re.compile(
    r"\b(?:part[- ]time\s+job|work\s+from\s+home|daily\s+income|earn\s+rs\.?\s*\d+|\bgoogle\s+maps?\s+review|\brating\s+task|ghar\s+baithe)\b.*"
    r"\b(?:whatsapp|telegram|wa\.me|contact\s+hr|contact\s+manager)\b",
    re.IGNORECASE,
)


def evaluate_rules(
    raw_text: str, sender_header: Optional[str] = None
) -> List[RuleSignal]:
    """
    Evaluates raw text and sender header against deterministic security rules.
    Returns a list of fired RuleSignals with severity and evidence.
    """
    signals: List[RuleSignal] = []
    norm_res = analyze_and_normalize(raw_text)
    sender_res = parse_sender_header(sender_header)
    cleaned = norm_res.cleaned_text
    single_line_clean = " ".join(cleaned.split())

    # RULE 1: Legitimate Delivery OTP Context (High-priority Context Filter)
    deliv_match = RE_RULE_DELIVERY_OTP.search(single_line_clean)
    if deliv_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-DELIVERY-OTP",
                signal_type="LEGIT_DELIVERY_OTP",
                severity="INFO",
                confidence=0.92,
                evidence=deliv_match.group(0)[:80],
                metadata={"context": "DELIVERY_VERIFICATION"},
            )
        )

    # RULE 2: Legitimate OTP Warning Context
    warn_match = RE_RULE_OTP_LEGIT_WARNING.search(single_line_clean)
    if warn_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-OTP-WARN",
                signal_type="LEGIT_OTP_WARNING",
                severity="INFO",
                confidence=0.95,
                evidence=warn_match.group(0)[:80],
                metadata={"context": "BANK_SECURITY_WARNING"},
            )
        )

    # RULE 3: Reverse OTP Disclosure Attack (Only if NOT a legitimate delivery OTP and NOT a legitimate warning)
    theft_match = RE_RULE_OTP_THEFT.search(single_line_clean)
    if theft_match and not deliv_match and not warn_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-OTP-DISCLOSURE",
                signal_type="OTP_DISCLOSURE_REQUEST",
                severity="HIGH",
                confidence=0.98,
                evidence=theft_match.group(0)[:80],
                metadata={"threat": "CREDENTIAL_SOCIAL_ENGINEERING"},
            )
        )

    # RULE 4: Electricity Disconnection Scam
    elec_match = RE_RULE_ELECTRICITY_DISCONNECT.search(single_line_clean)
    if elec_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-ELECTRICITY-DISCONNECT",
                signal_type="ELECTRICITY_SCAM_THREAT",
                severity="CRITICAL",
                confidence=0.99,
                evidence=elec_match.group(0)[:80],
                metadata={"threat": "UTILITY_DISCONNECTION_EXTORTION"},
            )
        )

    # RULE 5: Bank KYC / PAN Suspension Phishing Link
    kyc_match = RE_RULE_BANK_KYC_LINK.search(single_line_clean)
    if kyc_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-BANK-KYC-PHISH",
                signal_type="BANK_KYC_PHISHING",
                severity="CRITICAL",
                confidence=0.98,
                evidence=kyc_match.group(0)[:80],
                metadata={"threat": "CREDENTIAL_HARVESTING_LINK"},
            )
        )

    # RULE 6: APK Malware Dropper
    apk_match = RE_RULE_APK_DROPPER.search(single_line_clean)
    if apk_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-APK-DROPPER",
                signal_type="APK_MALWARE_DROPPER",
                severity="HIGH",
                confidence=0.95,
                evidence=apk_match.group(0)[:80],
                metadata={"threat": "MALWARE_INSTALLATION"},
            )
        )

    # RULE 7: UPI Collect / Enter PIN Fraud
    upi_match = RE_RULE_UPI_COLLECT.search(single_line_clean)
    if upi_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-UPI-COLLECT",
                signal_type="UPI_COLLECT_FRAUD",
                severity="CRITICAL",
                confidence=0.98,
                evidence=upi_match.group(0)[:80],
                metadata={"threat": "UNAUTHORIZED_MONEY_DEBIT"},
            )
        )

    # RULE 8: Part-time Job Review Task Scam
    job_match = RE_RULE_TASK_JOB_SCAM.search(single_line_clean)
    if job_match:
        signals.append(
            RuleSignal(
                rule_id="RULE-TASK-JOB-SCAM",
                signal_type="JOB_TASK_SCAM",
                severity="HIGH",
                confidence=0.95,
                evidence=job_match.group(0)[:80],
                metadata={"threat": "TASK_BASED_ADVANCE_FEE_FRAUD"},
            )
        )

    return signals
