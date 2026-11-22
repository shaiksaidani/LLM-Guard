"""
Data Loss Prevention (DLP) Module for LLM-Guard.
Provides a unified interface for inspecting incoming user prompts
and outgoing generative LLM responses.
"""

from typing import Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field

from modules.dlp.config import (
    DLPConfig,
    SensitiveDataCategory,
    MaskingMode,
    DEFAULT_CONFIG,
)
from modules.dlp.detector import DLPDetector, DetectionItem
from modules.dlp.masker import DLPMasker
from modules.dlp.response_scanner import DLPResponseScanner, ResponseScanReport


# ==============================================================================
# PROMPT SCAN RESULT MODEL
# ==============================================================================

class PromptScanReport(BaseModel):
    """
    Structured response returned after scanning an incoming user prompt.
    Supports both attribute access (result.sanitized_prompt) and dict key access (result['sanitized_prompt']).
    """
    success: bool = Field(default=True, description="Scan execution success status.")
    sensitive_data_detected: bool = Field(description="True if sensitive data was found.")
    sanitized_prompt: str = Field(description="Sanitized prompt ready for downstream LLM processing.")
    detections: List[Dict[str, Any]] = Field(default_factory=list, description="Sanitized detection details.")
    detection_count: int = Field(ge=0, description="Total sensitive items detected.")
    risk_level: str = Field(default="NONE", description="Assessed risk level.")

    model_config = {
        "extra": "ignore"
    }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __iter__(self):
        return iter(self.model_dump())

    def keys(self):
        return self.model_dump().keys()

    def values(self):
        return self.model_dump().values()

    def items(self):
        return self.model_dump().items()

    def __contains__(self, key: str) -> bool:
        return key in self.model_dump()

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to standard Python dictionary."""
        return self.model_dump()


# ==============================================================================
# UNIFIED DLP FACADE
# ==============================================================================

class DLP:
    """
    Unified Data Loss Prevention engine for LLM-Guard.
    Designed for seamless integration into FastAPI gateways, prompt firewalls,
    and agentic pipelines.
    """

    def __init__(self, config: Optional[DLPConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.detector = DLPDetector(self.config)
        self.masker = DLPMasker(self.config)
        self.response_scanner = DLPResponseScanner(
            config=self.config,
            detector=self.detector,
            masker=self.masker
        )

    def scan_prompt(
        self,
        prompt: Any,
        mode: Union[MaskingMode, str] = MaskingMode.FULL,
        custom_labels: Optional[Dict[SensitiveDataCategory, str]] = None
    ) -> PromptScanReport:
        """
        Scans an incoming user prompt, detects sensitive entities, and sanitizes it.

        Args:
            prompt: Incoming user prompt string.
            mode: MaskingMode.FULL ('full') or MaskingMode.PARTIAL ('partial').
            custom_labels: Optional dictionary mapping category enums to custom replacement tags.

        Returns:
            PromptScanReport with sanitization details and the safe prompt.
        """
        # Convert string mode to enum if passed as string
        if isinstance(mode, str):
            try:
                mode_enum = MaskingMode(mode.lower())
            except ValueError:
                mode_enum = MaskingMode.FULL
        else:
            mode_enum = mode

        # Safe handling of non-string and empty inputs
        if not isinstance(prompt, str) or not prompt.strip():
            safe_text = "" if prompt is None or not isinstance(prompt, str) else prompt
            return PromptScanReport(
                success=True,
                sensitive_data_detected=False,
                sanitized_prompt=safe_text,
                detections=[],
                detection_count=0,
                risk_level="NONE"
            )

        try:
            # 1. Detect sensitive data patterns
            detections: List[DetectionItem] = self.detector.detect(prompt)
            has_sensitive = len(detections) > 0

            # 2. Mask detected sensitive information
            sanitized = self.masker.mask(
                text=prompt,
                detections=detections,
                mode=mode_enum,
                custom_labels=custom_labels
            )

            # 3. Determine risk level
            cat_enums = [d.category for d in detections]
            risk = self.response_scanner._calculate_risk_level(cat_enums)

            # 4. Generate structured detection entries (no raw values)
            detection_list = []
            for d in detections:
                detection_list.append({
                    "category": d.category.value,
                    "masked": True,
                    "confidence": round(d.confidence, 2),
                    "description": d.description,
                    "span": [d.start, d.end]
                })

            return PromptScanReport(
                success=True,
                sensitive_data_detected=has_sensitive,
                sanitized_prompt=sanitized,
                detections=detection_list,
                detection_count=len(detections),
                risk_level=risk
            )

        except Exception as err:
            # Safe failure mode: never expose raw prompt or secrets in exception strings
            return PromptScanReport(
                success=False,
                sensitive_data_detected=False,
                sanitized_prompt=str(prompt) if isinstance(prompt, str) else "",
                detections=[{"error": f"DLP prompt scan failed safely: {type(err).__name__}"}],
                detection_count=0,
                risk_level="HIGH"
            )

    def scan_response(
        self,
        response: Any,
        mode: Union[MaskingMode, str] = MaskingMode.FULL,
        custom_labels: Optional[Dict[SensitiveDataCategory, str]] = None
    ) -> ResponseScanReport:
        """
        Scans an outgoing LLM response for inadvertent data leakage and sanitizes it.

        Args:
            response: Outgoing LLM response string.
            mode: MaskingMode.FULL ('full') or MaskingMode.PARTIAL ('partial').
            custom_labels: Optional dictionary mapping category enums to custom replacement tags.

        Returns:
            ResponseScanReport with detection report and sanitized response.
        """
        if isinstance(mode, str):
            try:
                mode_enum = MaskingMode(mode.lower())
            except ValueError:
                mode_enum = MaskingMode.FULL
        else:
            mode_enum = mode

        return self.response_scanner.scan(
            response_text=response,
            mode=mode_enum,
            custom_labels=custom_labels
        )


__all__ = [
    "DLP",
    "DLPConfig",
    "SensitiveDataCategory",
    "MaskingMode",
    "DLPDetector",
    "DLPMasker",
    "DLPResponseScanner",
    "PromptScanReport",
    "ResponseScanReport",
    "DetectionItem",
]
