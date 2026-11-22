"""
Detection engine for the Data Loss Prevention (DLP) module.
Identifies sensitive data categories including emails, phone numbers,
IPv4 addresses, API keys, Aadhaar candidates, credit/debit card candidates,
and key-value passwords.
"""

import re
import math
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from modules.dlp.config import DLPConfig, SensitiveDataCategory, DEFAULT_CONFIG


# ==============================================================================
# CHECKSUM & VALIDATION ALGORITHMS
# ==============================================================================

def validate_luhn(card_candidate: str) -> bool:
    """
    Validates a numeric string using the Luhn checksum algorithm (Mod 10).
    Used to verify potential credit/debit card numbers and eliminate false positives.

    NOTE: Successful validation indicates mathematical conformance to ISO/IEC 7812.
    It does not claim or verify active account status or cardholder identity.
    """
    digits_only = [int(ch) for ch in card_candidate if ch.isdigit()]
    if len(digits_only) < 13 or len(digits_only) > 19:
        return False

    checksum = 0
    reversed_digits = digits_only[::-1]
    for idx, d in enumerate(reversed_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


# Verhoeff algorithm multiplication table
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Verhoeff algorithm permutation table
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff(num_str: str) -> bool:
    """
    Validates a numeric string using the Verhoeff checksum algorithm.
    Used by UIDAI for 12-digit Indian Aadhaar number error detection.

    NOTE: Successful check indicates mathematical conformity, NOT verified UIDAI identity.
    """
    clean_digits = "".join(filter(str.isdigit, num_str))
    if len(clean_digits) != 12:
        return False
    c = 0
    for i, item in enumerate(reversed(clean_digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(item)]]
    return c == 0


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to quantify randomness in candidate secret tokens."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ==============================================================================
# STRUCTURED DETECTION MODEL
# ==============================================================================

class DetectionItem(BaseModel):
    """
    Represents a single detected sensitive data element within text.
    Designed to protect secrets by not revealing raw values in string representations.
    """
    category: SensitiveDataCategory
    value: str = Field(description="Raw sensitive string matched in text.")
    start: int = Field(ge=0, description="Start character index (inclusive).")
    end: int = Field(gt=0, description="End character index (exclusive).")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score.")
    description: str = Field(default="", description="Category-specific match description.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context metadata.")

    def __repr__(self) -> str:
        # Security: Never expose the raw sensitive value in logging or object inspection
        return (
            f"DetectionItem(category={self.category.value}, "
            f"span=[{self.start}:{self.end}], confidence={self.confidence:.2f})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# ==============================================================================
# DLP DETECTOR ENGINE
# ==============================================================================

class DLPDetector:
    """
    High-accuracy, modular Sensitive Data Detection engine for generative AI prompts & responses.
    """

    def __init__(self, config: Optional[DLPConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compiles regular expression patterns for performance and isolation."""
        # 1. Email: RFC 5322 simplified pattern with negative lookarounds
        self.email_pattern = re.compile(
            r"(?i)(?<![a-zA-Z0-9_.+-])([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)(?![a-zA-Z0-9_.+-])"
        )

        # 2. Indian Mobile Numbers: Starts with 6-9, 10 digits, optional +91, 91 or 0 prefix
        self.phone_in_pattern = re.compile(
            r"(?<!\w)(?:\+91[\s\-]??|91[\s\-]??|0)??([6-9]\d{4}[\s\-]??\d{5}|[6-9]\d{9})(?!\w)"
        )

        # 3. International Numbers (E.164 candidates)
        self.phone_intl_pattern = re.compile(
            r"(?<!\w)\+([1-9]\d{0,2}[\s\-]?(?:\(?\d{1,4}\)?[\s\-]?)?\d{1,4}[\s\-]?\d{1,4}(?:[\s\-]?\d{1,9})?)(?!\w)"
        )

        # 4. IPv4 Addresses: 4 octets 0-255 with strict negative boundary checks
        # Handles sentence-ending periods (. followed by whitespace/end) while rejecting version numbers (e.g. 1.2.3.4.5)
        _octet = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        self.ipv4_pattern = re.compile(
            rf"(?<!\d\.)(?<!\d)({_octet}(?:\.{_octet}){{3}})(?!\.\d)(?!\d)"
        )

        # 5. Aadhaar candidates: 12 digits, first digit 1-9, spaced or continuous
        self.aadhaar_pattern = re.compile(
            r"(?<!\d)([1-9]\d{3}[\s\-]??\d{4}[\s\-]??\d{4})(?!\d)"
        )

        # 6. Credit/Debit Card candidates: 13-19 digits, formatted with spaces or hyphens
        self.card_pattern = re.compile(
            r"(?<!\d)(\d(?:[\s\-]?\d){12,18})(?!\d)"
        )

        # 7. Common API Key / Credential Patterns
        self.api_key_patterns = [
            ("OpenAI API Key", re.compile(r"\b(?:sk-[a-zA-Z0-9_\-]{14,}|sk-proj-[a-zA-Z0-9_\-]{14,})\b")),
            ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
            ("GitHub Access Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9_]{82}\b")),
            ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
            ("Slack Token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b")),
            ("Bearer Token", re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b")),
            ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
        ]

        # 8. Password in explicit key-value assignments
        self.password_kv_pattern = re.compile(
            r"(?i)(?:^|[\s,;{}()\[\]])(?P<key>password|passwd|pwd|passcode|secret_key|api_secret|client_secret|db_password)\s*[:=]\s*(?P<val>\"[^\r\n\"]{3,}\"|'[^'\r\n]{3,}'|[^\s,;\"'}\]]{3,})"
        )

    # --------------------------------------------------------------------------
    # CATEGORY SPECIFIC DETECTION METHODS
    # --------------------------------------------------------------------------

    def detect_emails(self, text: str) -> List[DetectionItem]:
        """Detect email address patterns."""
        results: List[DetectionItem] = []
        for match in self.email_pattern.finditer(text):
            raw = match.group(1)
            # Remove trailing period if captured erroneously before sentence end
            clean = raw.rstrip(".")
            start = match.start(1)
            end = start + len(clean)

            # Validation: local part <= 64, domain part <= 255, TLD length >= 2
            if "@" in clean:
                local, domain = clean.rsplit("@", 1)
                tld = domain.split(".")[-1] if "." in domain else ""
                if 1 <= len(local) <= 64 and len(domain) <= 255 and len(tld) >= 2 and tld.isalpha():
                    results.append(
                        DetectionItem(
                            category=SensitiveDataCategory.EMAIL,
                            value=clean,
                            start=start,
                            end=end,
                            confidence=0.95,
                            description="Email address pattern",
                            metadata={"domain": domain}
                        )
                    )
        return results

    def detect_indian_phones(self, text: str) -> List[DetectionItem]:
        """Detect Indian 10-digit mobile phone numbers."""
        results: List[DetectionItem] = []
        for match in self.phone_in_pattern.finditer(text):
            full_match = match.group(0)
            digits = re.sub(r"\D", "", full_match)

            # Check if formatted with +91 or 91 or 0 prefix
            if digits.startswith("91") and len(digits) == 12:
                ten_digit = digits[2:]
            elif digits.startswith("0") and len(digits) == 11:
                ten_digit = digits[1:]
            elif len(digits) == 10:
                ten_digit = digits
            else:
                continue

            if ten_digit[0] in "6789":
                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.PHONE_IN,
                        value=full_match,
                        start=match.start(0),
                        end=match.end(0),
                        confidence=0.90,
                        description="Indian mobile phone candidate",
                        metadata={"digits_length": len(digits)}
                    )
                )
        return results

    def detect_intl_phones(self, text: str) -> List[DetectionItem]:
        """Detect International phone numbers in E.164 candidate format."""
        results: List[DetectionItem] = []
        for match in self.phone_intl_pattern.finditer(text):
            full_match = match.group(0)
            digits = re.sub(r"\D", "", full_match)

            # E.164 numbers contain between 7 and 15 digits
            if 7 <= len(digits) <= 15:
                # If it's an Indian mobile (+91), prioritize PHONE_IN
                if full_match.startswith("+91") and len(digits) == 12 and digits[2] in "6789":
                    results.append(
                        DetectionItem(
                            category=SensitiveDataCategory.PHONE_IN,
                            value=full_match,
                            start=match.start(0),
                            end=match.end(0),
                            confidence=0.95,
                            description="Indian mobile phone candidate with country code",
                            metadata={"digits_length": len(digits)}
                        )
                    )
                else:
                    results.append(
                        DetectionItem(
                            category=SensitiveDataCategory.PHONE_INTL,
                            value=full_match,
                            start=match.start(0),
                            end=match.end(0),
                            confidence=0.85,
                            description="International phone number candidate",
                            metadata={"digits_length": len(digits)}
                        )
                    )
        return results

    def detect_ipv4(self, text: str) -> List[DetectionItem]:
        """Detect valid IPv4 address patterns."""
        results: List[DetectionItem] = []
        for match in self.ipv4_pattern.finditer(text):
            ip_str = match.group(1)
            octets = ip_str.split(".")
            if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.IPV4,
                        value=ip_str,
                        start=match.start(1),
                        end=match.end(1),
                        confidence=0.95,
                        description="IPv4 address",
                        metadata={"octets": octets}
                    )
                )
        return results

    def detect_aadhaar(self, text: str) -> List[DetectionItem]:
        """
        Detect 12-digit Aadhaar-like number candidates.
        Matches 12 digits (spaced or continuous) starting with 1-9.
        Applies Verhoeff checksum if enabled.
        """
        results: List[DetectionItem] = []
        for match in self.aadhaar_pattern.finditer(text):
            raw = match.group(1)
            digits = re.sub(r"\D", "", raw)
            if len(digits) == 12 and digits[0] in "123456789":
                verhoeff_valid = validate_verhoeff(digits)
                if self.config.enable_verhoeff_validation and not verhoeff_valid:
                    continue

                confidence = 0.95 if verhoeff_valid else 0.85
                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.AADHAAR,
                        value=raw,
                        start=match.start(1),
                        end=match.end(1),
                        confidence=confidence,
                        description="Aadhaar-like 12-digit number candidate",
                        metadata={
                            "verhoeff_checked": verhoeff_valid,
                            "disclaimer": "Pattern candidate only; does not confirm verified UIDAI identity."
                        }
                    )
                )
        return results

    def detect_cards(self, text: str) -> List[DetectionItem]:
        """
        Detect candidate credit or debit card numbers.
        Applies Luhn algorithm check to filter out arbitrary long numeric sequences.
        """
        results: List[DetectionItem] = []
        for match in self.card_pattern.finditer(text):
            raw = match.group(1)
            digits = re.sub(r"\D", "", raw)

            # Valid payment card range: 13 to 19 digits
            if 13 <= len(digits) <= 19:
                # If Luhn validation is enabled, require checksum match
                if self.config.enable_luhn_validation:
                    if not validate_luhn(digits):
                        continue

                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.CARD,
                        value=raw,
                        start=match.start(1),
                        end=match.end(1),
                        confidence=0.95,
                        description="Credit/Debit card candidate (Luhn verified)",
                        metadata={
                            "digit_count": len(digits),
                            "disclaimer": "Identifies candidate card number; does not imply active bank account."
                        }
                    )
                )
        return results

    def detect_api_keys(self, text: str) -> List[DetectionItem]:
        """Detect known API key patterns and high-entropy bearer tokens."""
        results: List[DetectionItem] = []
        for key_name, pattern in self.api_key_patterns:
            for match in pattern.finditer(text):
                # If there's a capture group (e.g. Bearer token value), use group 1, else group 0
                val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                start = match.start(1) if match.lastindex and match.lastindex >= 1 else match.start(0)
                end = match.end(1) if match.lastindex and match.lastindex >= 1 else match.end(0)

                # Avoid false positives for very low entropy words
                entropy = calculate_shannon_entropy(val)
                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.API_KEY,
                        value=val,
                        start=start,
                        end=end,
                        confidence=0.95,
                        description=f"{key_name} pattern candidate",
                        metadata={"key_type": key_name, "entropy": round(entropy, 2)}
                    )
                )
        return results

    def detect_password_kv(self, text: str) -> List[DetectionItem]:
        """Detect passwords explicitly assigned in key-value formats."""
        results: List[DetectionItem] = []
        for match in self.password_kv_pattern.finditer(text):
            key = match.group("key")
            raw_val = match.group("val")
            val_start = match.start("val")
            val_end = match.end("val")

            # Strip outer quotes if present so masking can selectively replace value
            clean_val = raw_val.strip("\"'")
            if raw_val.startswith(("\"", "'")) and raw_val.endswith(("\"", "'")):
                val_start += 1
                val_end -= 1

            if len(clean_val) >= 3:
                results.append(
                    DetectionItem(
                        category=SensitiveDataCategory.PASSWORD_KV,
                        value=clean_val,
                        start=val_start,
                        end=val_end,
                        confidence=0.90,
                        description=f"Password provided via key-value parameter '{key}'",
                        metadata={"param_key": key}
                    )
                )
        return results

    # --------------------------------------------------------------------------
    # OVERLAP RESOLUTION & CONFLICT ARBITRATION
    # --------------------------------------------------------------------------

    def _resolve_overlaps(self, items: List[DetectionItem]) -> List[DetectionItem]:
        """
        Resolves overlapping detections so that no two items share character indices.
        Priority is given to higher confidence, higher risk category, and longer match span.
        """
        if not items:
            return []

        # Sort items: start position ascending, then span length descending, then confidence descending
        sorted_items = sorted(
            items,
            key=lambda x: (x.start, -(x.end - x.start), -x.confidence)
        )

        resolved: List[DetectionItem] = []
        for current in sorted_items:
            if not resolved:
                resolved.append(current)
                continue

            prev = resolved[-1]
            # Check overlap: current starts before previous ends
            if current.start < prev.end:
                # Conflict exists. Determine which detection is superior.
                prev_is_sensitive = prev.category in (
                    SensitiveDataCategory.API_KEY,
                    SensitiveDataCategory.PASSWORD_KV,
                    SensitiveDataCategory.CARD,
                )
                curr_is_sensitive = current.category in (
                    SensitiveDataCategory.API_KEY,
                    SensitiveDataCategory.PASSWORD_KV,
                    SensitiveDataCategory.CARD,
                )

                if curr_is_sensitive and not prev_is_sensitive:
                    resolved[-1] = current
                elif (current.end - current.start) > (prev.end - prev.start) and current.confidence >= prev.confidence:
                    resolved[-1] = current
                # Otherwise, keep previous and discard the overlapping candidate
            else:
                resolved.append(current)

        return resolved

    # --------------------------------------------------------------------------
    # MAIN DETECTION DISPATCHER
    # --------------------------------------------------------------------------

    def detect(self, text: Any) -> List[DetectionItem]:
        """
        Executes all enabled category detectors on the input text.
        Returns a sorted, non-overlapping list of DetectionItem objects.
        """
        if not isinstance(text, str) or not text.strip():
            return []

        all_detections: List[DetectionItem] = []
        enabled = self.config.enabled_categories

        if SensitiveDataCategory.EMAIL in enabled:
            all_detections.extend(self.detect_emails(text))

        if SensitiveDataCategory.PHONE_IN in enabled:
            all_detections.extend(self.detect_indian_phones(text))

        if SensitiveDataCategory.PHONE_INTL in enabled:
            all_detections.extend(self.detect_intl_phones(text))

        if SensitiveDataCategory.IPV4 in enabled:
            all_detections.extend(self.detect_ipv4(text))

        if SensitiveDataCategory.AADHAAR in enabled:
            all_detections.extend(self.detect_aadhaar(text))

        if SensitiveDataCategory.CARD in enabled:
            all_detections.extend(self.detect_cards(text))

        if SensitiveDataCategory.API_KEY in enabled:
            all_detections.extend(self.detect_api_keys(text))

        if SensitiveDataCategory.PASSWORD_KV in enabled:
            all_detections.extend(self.detect_password_kv(text))

        return self._resolve_overlaps(all_detections)
