"""
Configuration module for Data Loss Prevention (DLP) engine.
Defines supported categories, masking labels, partial masking rules,
and operational thresholds.
"""

from enum import Enum
from typing import Dict, Set, Any
from pydantic import BaseModel, Field


class SensitiveDataCategory(str, Enum):
    """Supported sensitive data categories for the DLP engine."""
    EMAIL = "EMAIL"
    PHONE_IN = "PHONE_IN"
    PHONE_INTL = "PHONE_INTL"
    IPV4 = "IPV4"
    API_KEY = "API_KEY"
    AADHAAR = "AADHAAR"
    CARD = "CARD"
    PASSWORD_KV = "PASSWORD_KV"


class MaskingMode(str, Enum):
    """Supported masking modes."""
    FULL = "full"
    PARTIAL = "partial"


class DLPConfig(BaseModel):
    """
    Centralized configuration for DLP detector, masker, and response scanner.
    """
    # Enabled detection categories
    enabled_categories: Set[SensitiveDataCategory] = Field(
        default_factory=lambda: set(SensitiveDataCategory),
        description="Set of sensitive data categories active during scanning."
    )

    # Full redaction labels mapped to each category
    masking_labels: Dict[SensitiveDataCategory, str] = Field(
        default_factory=lambda: {
            SensitiveDataCategory.EMAIL: "[EMAIL]",
            SensitiveDataCategory.PHONE_IN: "[PHONE]",
            SensitiveDataCategory.PHONE_INTL: "[PHONE]",
            SensitiveDataCategory.IPV4: "[IP_ADDRESS]",
            SensitiveDataCategory.API_KEY: "[API_KEY]",
            SensitiveDataCategory.AADHAAR: "[AADHAAR]",
            SensitiveDataCategory.CARD: "[CARD]",
            SensitiveDataCategory.PASSWORD_KV: "[PASSWORD]",
        },
        description="Text placeholders used during full masking."
    )

    # Categories that MUST ALWAYS be fully redacted, even in partial masking mode
    # Security requirement: Credentials, API keys, and passwords must never be partially exposed
    always_fully_redact_categories: Set[SensitiveDataCategory] = Field(
        default_factory=lambda: {
            SensitiveDataCategory.API_KEY,
            SensitiveDataCategory.PASSWORD_KV,
        },
        description="Categories that must never be partially masked due to critical security risk."
    )

    # Checksum and verification settings to minimize false positives
    enable_luhn_validation: bool = Field(
        default=True,
        description="Use Luhn checksum algorithm to validate potential credit/debit card numbers."
    )

    enable_verhoeff_validation: bool = Field(
        default=False,
        description="Enforce Verhoeff checksum algorithm on 12-digit Aadhaar candidates. "
                    "When False, Aadhaar candidates are detected via structural rules (12 digits, "
                    "starts with 2-9, spaced or unspaced) and assigned standard confidence."
    )

    # Entropy threshold for generic API key detection (Shannon entropy)
    entropy_threshold: float = Field(
        default=3.5,
        description="Minimum Shannon entropy threshold for identifying high-entropy token candidates."
    )

    # Default masking mode
    default_masking_mode: MaskingMode = Field(
        default=MaskingMode.FULL,
        description="Default masking mode applied when not explicitly specified."
    )

    # Risk level weightings for reporting
    category_risk_levels: Dict[SensitiveDataCategory, str] = Field(
        default_factory=lambda: {
            SensitiveDataCategory.PASSWORD_KV: "CRITICAL",
            SensitiveDataCategory.API_KEY: "CRITICAL",
            SensitiveDataCategory.CARD: "HIGH",
            SensitiveDataCategory.AADHAAR: "HIGH",
            SensitiveDataCategory.EMAIL: "MEDIUM",
            SensitiveDataCategory.PHONE_IN: "MEDIUM",
            SensitiveDataCategory.PHONE_INTL: "MEDIUM",
            SensitiveDataCategory.IPV4: "LOW",
        },
        description="Security risk severity for each detected data category."
    )

    model_config = {
        "arbitrary_types_allowed": True
    }


# Singleton default configuration instance
DEFAULT_CONFIG = DLPConfig()
