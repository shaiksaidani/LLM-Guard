
import re
from pydantic import BaseModel
from typing import List

from modules.threat_detection.config import (
    ThreatCategory,
    ThreatLevel,
    ThreatDetectionConfig
)


class ThreatDetectionResult(BaseModel):
    is_threat: bool
    threat_categories: List[ThreatCategory]
    threat_score: int
    threat_level: ThreatLevel
    matched_patterns: List[str]
    reasons: List[str]


class ThreatDetector:

    def __init__(self, config=None):
        self.config = config or ThreatDetectionConfig()

        self.patterns = {
            ThreatCategory.JAILBREAK: [
                r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
                r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
                r"reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions)",
                r"bypass\s+(your\s+)?(safety|security)\s+(rules|filters)",
                r"developer\s+mode"
            ],

            ThreatCategory.PROMPT_INJECTION: [
                r"ignore\s+the\s+above\s+and\s+follow",
                r"new\s+instructions\s*:",
                r"system\s+prompt\s*:",
                r"do\s+not\s+follow\s+(the\s+)?(user|previous)\s+instructions",
                r"override\s+(the\s+)?system\s+instructions"
            ]
        }

    def detect(self, prompt: str) -> ThreatDetectionResult:

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        if len(prompt) > self.config.max_prompt_length:
            raise ValueError("Prompt exceeds maximum allowed length.")

        detected_categories = []
        matched_patterns = []
        reasons = []
        score = 0

        category_scores = {
            ThreatCategory.JAILBREAK: 60,
            ThreatCategory.PROMPT_INJECTION: 55
        }

        for category, patterns in self.patterns.items():

            if category not in self.config.enabled_categories:
                continue

            category_matches = []

            for pattern in patterns:
                if re.search(pattern, prompt, re.IGNORECASE):
                    category_matches.append(pattern)

            if category_matches:
                detected_categories.append(category)
                matched_patterns.extend(category_matches)

                score += category_scores[category]

                reasons.append(
                    f"Detected {category.value} pattern."
                )

        if len(matched_patterns) > 1:
            score += 15 * (len(matched_patterns) - 1)

        score = min(score, 100)

        if score >= self.config.malicious_threshold:
            threat_level = ThreatLevel.MALICIOUS
        elif score >= self.config.suspicious_threshold:
            threat_level = ThreatLevel.SUSPICIOUS
        else:
            threat_level = ThreatLevel.SAFE

        return ThreatDetectionResult(
            is_threat=score >= self.config.suspicious_threshold,
            threat_categories=detected_categories,
            threat_score=score,
            threat_level=threat_level,
            matched_patterns=matched_patterns,
            reasons=reasons
        )
