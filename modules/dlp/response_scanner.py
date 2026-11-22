"""
LLM Response Scanner for Data Loss Prevention (DLP).
Scans generated responses from Large Language Models for exposed credentials,
PII, and sensitive infrastructure details, and produces sanitized outputs
paired with structured security reports.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from modules.dlp.config import DLPConfig, SensitiveDataCategory, MaskingMode, DEFAULT_CONFIG
from modules.dlp.detector import DLPDetector, DetectionItem
from modules.dlp.masker import DLPMasker


class ResponseScanReport(BaseModel):
    """
    Structured security evaluation report for scanned LLM responses.
    Provides dictionary-like access for seamless FastAPI response handling.
    """
    success: bool = Field(default=True, description="Indicates if the scan completed without errors.")
    sensitive_data_detected: bool = Field(description="True if any sensitive data was detected.")
    sanitized_response: str = Field(description="Response text with sensitive elements masked.")
    detection_count: int = Field(ge=0, description="Total number of sensitive items detected.")
    categories: List[str] = Field(default_factory=list, description="Unique categories detected.")
    risk_level: str = Field(default="NONE", description="Overall risk rating: NONE, LOW, MEDIUM, HIGH, CRITICAL.")
    detections: List[Dict[str, Any]] = Field(default_factory=list, description="Sanitized detection details.")
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of scan execution."
    )

    model_config = {
        "extra": "ignore"
    }

    # Enable dictionary-like indexing for backwards and cross-framework compatibility
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


class DLPResponseScanner:
    """
    Scans outgoing LLM responses, sanitizes discovered PII/credentials,
    and produces actionable security metrics.
    """

    def __init__(
        self,
        config: Optional[DLPConfig] = None,
        detector: Optional[DLPDetector] = None,
        masker: Optional[DLPMasker] = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.detector = detector or DLPDetector(self.config)
        self.masker = masker or DLPMasker(self.config)

    def _calculate_risk_level(self, detected_categories: List[SensitiveDataCategory]) -> str:
        """Determines highest severity risk present in scan results."""
        if not detected_categories:
            return "NONE"

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        highest_severity = "NONE"

        for cat in detected_categories:
            risk = self.config.category_risk_levels.get(cat, "LOW")
            if severity_order.index(risk) < severity_order.index(highest_severity):
                highest_severity = risk

        return highest_severity

    def scan(
        self,
        response_text: Any,
        mode: Optional[MaskingMode] = None,
        custom_labels: Optional[Dict[SensitiveDataCategory, str]] = None
    ) -> ResponseScanReport:
        """
        Scans an LLM response string for sensitive data leakage.

        Args:
            response_text: The raw LLM text response.
            mode: Full or partial masking mode.
            custom_labels: Optional category-to-replacement mapping overrides.

        Returns:
            ResponseScanReport containing sanitization status and security metrics.
        """
        # Handle non-string and empty inputs safely
        if not isinstance(response_text, str) or not response_text.strip():
            safe_text = "" if response_text is None or not isinstance(response_text, str) else response_text
            return ResponseScanReport(
                success=True,
                sensitive_data_detected=False,
                sanitized_response=safe_text,
                detection_count=0,
                categories=[],
                risk_level="NONE",
                detections=[]
            )

        try:
            # 1. Detect sensitive data patterns
            detections: List[DetectionItem] = self.detector.detect(response_text)
            has_sensitive = len(detections) > 0

            # 2. Mask detected sensitive information
            sanitized = self.masker.mask(
                text=response_text,
                detections=detections,
                mode=mode,
                custom_labels=custom_labels
            )

            # 3. Compile report metadata
            unique_categories = sorted(list({d.category.value for d in detections}))
            cat_enums = [d.category for d in detections]
            risk = self._calculate_risk_level(cat_enums)

            # Build safe detection summaries (NEVER include raw values in output reports)
            detection_summaries = []
            for d in detections:
                safe_preview = self.masker.get_replacement(d, MaskingMode.PARTIAL)
                detection_summaries.append({
                    "category": d.category.value,
                    "masked": True,
                    "confidence": round(d.confidence, 2),
                    "description": d.description,
                    "preview": safe_preview,
                    "span": [d.start, d.end]
                })

            return ResponseScanReport(
                success=True,
                sensitive_data_detected=has_sensitive,
                sanitized_response=sanitized,
                detection_count=len(detections),
                categories=unique_categories,
                risk_level=risk,
                detections=detection_summaries
            )

        except Exception as err:
            # Safe exception handling: never leak input text or secrets in error messages
            return ResponseScanReport(
                success=False,
                sensitive_data_detected=False,
                sanitized_response=str(response_text) if isinstance(response_text, str) else "",
                detection_count=0,
                categories=[],
                risk_level="HIGH",
                detections=[{"error": f"DLP response scan failed safely: {type(err).__name__}"}]
            )
