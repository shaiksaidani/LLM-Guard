"""
Masking and redaction engine for the Data Loss Prevention (DLP) module.
Applies safe reverse-position replacement to preserve document integrity,
supporting full redaction, partial masking, and custom label mapping.
"""

import re
from typing import List, Dict, Optional, Any
from modules.dlp.config import DLPConfig, SensitiveDataCategory, MaskingMode, DEFAULT_CONFIG
from modules.dlp.detector import DetectionItem


class DLPMasker:
    """
    Engine responsible for redacting or obfuscating detected sensitive elements.
    """

    def __init__(self, config: Optional[DLPConfig] = None):
        self.config = config or DEFAULT_CONFIG

    # --------------------------------------------------------------------------
    # PARTIAL MASKING GENERATORS
    # --------------------------------------------------------------------------

    @staticmethod
    def _partial_mask_email(value: str) -> str:
        """
        Partially masks an email (e.g. 'lokesh@gmail.com' -> 'l***h@gmail.com').
        """
        if "@" not in value:
            return "[EMAIL]"
        local_part, domain = value.rsplit("@", 1)
        if len(local_part) <= 1:
            masked_local = "*"
        elif len(local_part) == 2:
            masked_local = f"{local_part[0]}*"
        else:
            masked_local = f"{local_part[0]}{'*' * (len(local_part) - 2)}{local_part[-1]}"
        return f"{masked_local}@{domain}"

    @staticmethod
    def _partial_mask_phone(value: str) -> str:
        """
        Partially masks a phone number, preserving the last 4 digits (e.g. '******3210').
        """
        digits = re.findall(r"\d", value)
        if len(digits) <= 4:
            return "****"
        # Mask all digits except the last 4
        unmasked_count = 0
        result_chars = []
        for ch in reversed(value):
            if ch.isdigit():
                if unmasked_count < 4:
                    result_chars.append(ch)
                    unmasked_count += 1
                else:
                    result_chars.append("*")
            else:
                result_chars.append(ch)
        return "".join(reversed(result_chars))

    @staticmethod
    def _partial_mask_ipv4(value: str) -> str:
        """
        Partially masks an IPv4 address (e.g. '192.168.1.10' -> '192.168.*.*').
        """
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "[IP_ADDRESS]"

    @staticmethod
    def _partial_mask_aadhaar(value: str) -> str:
        """
        Partially masks an Aadhaar-like number, preserving only the last 4 digits.
        (e.g. '1234 5678 9012' -> '**** **** 9012' or '********9012').
        """
        unmasked_count = 0
        result_chars = []
        for ch in reversed(value):
            if ch.isdigit():
                if unmasked_count < 4:
                    result_chars.append(ch)
                    unmasked_count += 1
                else:
                    result_chars.append("*")
            else:
                result_chars.append(ch)
        return "".join(reversed(result_chars))

    @staticmethod
    def _partial_mask_card(value: str) -> str:
        """
        Partially masks a credit card, preserving first 4 and last 4 digits.
        (e.g. '4111111111111111' -> '4111********1111').
        """
        digits = [i for i, ch in enumerate(value) if ch.isdigit()]
        if len(digits) < 8:
            return "[CARD]"
        first_keep = set(digits[:4])
        last_keep = set(digits[-4:])

        result = []
        for i, ch in enumerate(value):
            if ch.isdigit():
                if i in first_keep or i in last_keep:
                    result.append(ch)
                else:
                    result.append("*")
            else:
                result.append(ch)
        return "".join(result)

    # --------------------------------------------------------------------------
    # REPLACEMENT VALUE RESOLUTION
    # --------------------------------------------------------------------------

    def get_replacement(
        self,
        item: DetectionItem,
        mode: MaskingMode,
        custom_labels: Optional[Dict[SensitiveDataCategory, str]] = None
    ) -> str:
        """
        Determines the replacement string for a detected item based on category and masking mode.
        """
        labels = custom_labels or self.config.masking_labels
        default_label = labels.get(item.category, f"[{item.category.value}]")

        # Security Enforcement:
        # High-risk credentials and passwords MUST ALWAYS be fully redacted
        if item.category in self.config.always_fully_redact_categories:
            return default_label

        if mode == MaskingMode.FULL:
            return default_label

        if mode == MaskingMode.PARTIAL:
            if item.category == SensitiveDataCategory.EMAIL:
                return self._partial_mask_email(item.value)
            elif item.category in (SensitiveDataCategory.PHONE_IN, SensitiveDataCategory.PHONE_INTL):
                return self._partial_mask_phone(item.value)
            elif item.category == SensitiveDataCategory.IPV4:
                return self._partial_mask_ipv4(item.value)
            elif item.category == SensitiveDataCategory.AADHAAR:
                return self._partial_mask_aadhaar(item.value)
            elif item.category == SensitiveDataCategory.CARD:
                return self._partial_mask_card(item.value)
            else:
                return default_label

        return default_label

    # --------------------------------------------------------------------------
    # SAFE REVERSE-POSITION STRING MASKING
    # --------------------------------------------------------------------------

    def mask(
        self,
        text: str,
        detections: List[DetectionItem],
        mode: Optional[MaskingMode] = None,
        custom_labels: Optional[Dict[SensitiveDataCategory, str]] = None
    ) -> str:
        """
        Safely applies redactions to the input text based on detection span coordinates.

        Algorithm:
        1. Sort detections in descending order of their start index.
        2. Replace substrings from end to beginning.
        3. This ensures prior character replacements do not alter subsequent offsets.
        """
        if not isinstance(text, str) or not text:
            return "" if text is None else text

        if not detections:
            return text

        active_mode = mode or self.config.default_masking_mode

        # Sort descending by start index to maintain index validity during replacement
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        sanitized = text
        for item in sorted_detections:
            # Validate boundaries against current text bounds
            if item.start < 0 or item.end > len(sanitized) or item.start >= item.end:
                continue

            replacement = self.get_replacement(item, active_mode, custom_labels)
            sanitized = sanitized[:item.start] + replacement + sanitized[item.end:]

        return sanitized
