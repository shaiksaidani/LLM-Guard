
from enum import Enum
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    JAILBREAK = "JAILBREAK"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ThreatDetectionConfig(BaseModel):
    enabled_categories: set[ThreatCategory] = Field(
        default_factory=lambda: set(ThreatCategory)
    )

    suspicious_threshold: int = 30
    malicious_threshold: int = 70

    max_prompt_length: int = 4000
