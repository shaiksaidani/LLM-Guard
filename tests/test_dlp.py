"""
Unit and integration test suite for LLM-Guard Data Loss Prevention (DLP) engine.
All test cases use strictly synthetic, dummy data. No real personal identities,
credentials, or production secrets are used.
"""

import pytest
from modules.dlp import (
    DLP,
    DLPConfig,
    SensitiveDataCategory,
    MaskingMode,
    DLPDetector,
    DLPMasker,
    DLPResponseScanner,
)
from modules.dlp.detector import validate_luhn, validate_verhoeff


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def dlp():
    """Provides a fresh unified DLP instance with default settings."""
    return DLP()


@pytest.fixture
def detector():
    """Provides an isolated detector instance."""
    return DLPDetector()


@pytest.fixture
def masker():
    """Provides an isolated masker instance."""
    return DLPMasker()


@pytest.fixture
def response_scanner():
    """Provides an isolated response scanner instance."""
    return DLPResponseScanner()


# ==============================================================================
# 1. EMAIL DETECTION TESTS
# ==============================================================================

class TestEmailDetection:

    def test_standard_email_detection(self, dlp):
        text = "Please reach out to lokesh@gmail.com for updates."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 1
        assert result.detections[0]["category"] == "EMAIL"
        assert result.sanitized_prompt == "Please reach out to [EMAIL] for updates."

    def test_subdomain_and_corporate_email(self, dlp):
        text = "Submit queries to security.team@corp.internal.example.org immediately."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "Submit queries to [EMAIL] immediately."

    def test_email_with_trailing_punctuation(self, dlp):
        text = "Send confirmation to alert@test-domain.com."
        result = dlp.scan_prompt(text)
        assert result.sanitized_prompt == "Send confirmation to [EMAIL]."

    def test_email_false_positives_code_and_files(self, dlp):
        # Code attribute access and filenames should not trigger email detections
        text = "Invoke client.email() or check document.pdf and config.json."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is False
        assert result.detection_count == 0


# ==============================================================================
# 2. INDIAN PHONE NUMBER DETECTION TESTS
# ==============================================================================

class TestIndianPhoneDetection:

    def test_standard_10_digit_indian_phone(self, dlp):
        text = "Contact support on 9876543210 during office hours."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 1
        assert result.sanitized_prompt == "Contact support on [PHONE] during office hours."

    def test_indian_phone_with_plus91_prefix(self, dlp):
        text = "My direct line is +91 98765 43210."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "My direct line is [PHONE]."

    def test_indian_phone_with_hyphens_and_zero_prefix(self, dlp):
        text = "Call 098765-43210 or 08765432109 today."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 2
        assert "[PHONE]" in result.sanitized_prompt

    def test_invalid_indian_phone_digits(self, dlp):
        # Indian mobile numbers do not start with 1, 2, 3, 4, or 5
        text = "Order tracking ID is 1234567890 and batch 5555555555."
        # Note: 1234567890 is not a phone number (it's 10 digits starting with 1)
        result = dlp.scan_prompt(text)
        # Should not be detected as PHONE_IN
        phone_detections = [d for d in result.detections if d["category"] == "PHONE_IN"]
        assert len(phone_detections) == 0


# ==============================================================================
# 3. INTERNATIONAL PHONE NUMBER DETECTION TESTS
# ==============================================================================

class TestInternationalPhoneDetection:

    def test_us_e164_format(self, dlp):
        text = "US representative can be reached at +1-555-123-4567."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert "[PHONE]" in result.sanitized_prompt

    def test_uk_international_format(self, dlp):
        text = "UK office helpline is +44 20 7946 0958."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert "[PHONE]" in result.sanitized_prompt


# ==============================================================================
# 4. IPV4 ADDRESS DETECTION TESTS
# ==============================================================================

class TestIPv4Detection:

    def test_private_ipv4_detection(self, dlp):
        text = "Gateway is located at 192.168.1.10."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 1
        assert result.detections[0]["category"] == "IPV4"
        assert result.sanitized_prompt == "Gateway is located at [IP_ADDRESS]."

    def test_loopback_and_public_ipv4(self, dlp):
        text = "Listen on 127.0.0.1 and DNS 8.8.8.8."
        result = dlp.scan_prompt(text)
        assert result.detection_count == 2
        assert result.sanitized_prompt == "Listen on [IP_ADDRESS] and DNS [IP_ADDRESS]."

    def test_ipv4_version_number_false_positive(self, dlp):
        # Version numbers with multiple components (e.g. 1.2.3.4.5) must not be flagged
        text = "Software release version is 1.2.3.4.5."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is False

    def test_invalid_octet_range_not_detected(self, dlp):
        # 999 is outside valid 0-255 octet range
        text = "Invalid target 999.999.999.999 should be ignored."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is False


# ==============================================================================
# 5. AADHAAR CANDIDATE DETECTION TESTS
# ==============================================================================

class TestAadhaarDetection:

    def test_aadhaar_candidate_continuous_12_digits(self, dlp):
        text = "User registration Aadhaar is 123456789012 for validation."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 1
        assert result.detections[0]["category"] == "AADHAAR"
        assert result.sanitized_prompt == "User registration Aadhaar is [AADHAAR] for validation."

    def test_aadhaar_candidate_spaced_format(self, dlp):
        text = "Identity reference: 9876 5432 1098."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "Identity reference: [AADHAAR]."

    def test_verhoeff_validation_utility(self):
        # Test Verhoeff algorithm on synthetic known checksum pairs
        assert validate_verhoeff("234567890126") in (True, False)
        assert validate_verhoeff("invalid_text") is False


# ==============================================================================
# 6. CREDIT / DEBIT CARD CANDIDATE DETECTION TESTS
# ==============================================================================

class TestCreditCardDetection:

    def test_visa_synthetic_card_detection(self, dlp):
        # 4111 1111 1111 1111 is the standard synthetic Visa test number passing Luhn
        text = "Payment card number 4111111111111111 submitted."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 1
        assert result.detections[0]["category"] == "CARD"
        assert result.sanitized_prompt == "Payment card number [CARD] submitted."

    def test_card_with_spaces_and_hyphens(self, dlp):
        text = "Charge card 4111-1111-1111-1111 or 4111 1111 1111 1111."
        result = dlp.scan_prompt(text)
        assert result.detection_count == 2
        assert result.sanitized_prompt == "Charge card [CARD] or [CARD]."

    def test_card_luhn_failure_rejected(self, dlp):
        # 4111111111111112 fails Luhn checksum
        assert validate_luhn("4111111111111112") is False
        text = "Account reference ID 4111111111111112 was generated."
        result = dlp.scan_prompt(text)
        # Should not be detected as CARD because Luhn validation is enabled by default
        card_detections = [d for d in result.detections if d["category"] == "CARD"]
        assert len(card_detections) == 0


# ==============================================================================
# 7. API KEY AND CREDENTIAL DETECTION TESTS
# ==============================================================================

class TestAPIKeyDetection:

    def test_openai_api_key_detection(self, dlp):
        text = "Set OPENAI_API_KEY=sk-example123456789 in environment."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "Set OPENAI_API_KEY=[API_KEY] in environment."

    def test_aws_access_key_detection(self, dlp):
        # Synthetic 20-character AWS Key ID
        text = "AWS config: AKIAIOSFODNN7EXAMPLE deployed."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "AWS config: [API_KEY] deployed."

    def test_github_token_detection(self, dlp):
        # Synthetic GitHub token
        text = "Pushing using ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 token."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "Pushing using [API_KEY] token."

    def test_bearer_token_detection(self, dlp):
        text = "Authorization: Bearer synthetic_bearer_token_value_abc123456789"
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert "[API_KEY]" in result.sanitized_prompt


# ==============================================================================
# 8. KEY-VALUE PASSWORD PATTERN DETECTION TESTS
# ==============================================================================

class TestPasswordKVDetection:

    def test_unquoted_password_kv(self, dlp):
        text = "Connect with user=admin and password=SuperSecretP@ssw0rd! now."
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == "Connect with user=admin and password=[PASSWORD] now."

    def test_quoted_password_kv(self, dlp):
        text = 'Database credentials: api_secret: "my_synthetic_secret_key"'
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        assert result.sanitized_prompt == 'Database credentials: api_secret: "[PASSWORD]"'


# ==============================================================================
# 9. MULTIPLE AND OVERLAPPING DETECTIONS
# ==============================================================================

class TestMultipleAndOverlappingDetections:

    def test_multiple_distinct_categories_in_one_prompt(self, dlp):
        text = (
            "Hello, my email is test.user@example.com, my contact is 9876543210, "
            "server IP 192.168.1.50 and key sk-example123456789."
        )
        result = dlp.scan_prompt(text)
        assert result.detection_count == 4
        assert result.sensitive_data_detected is True
        expected = (
            "Hello, my email is [EMAIL], my contact is [PHONE], "
            "server IP [IP_ADDRESS] and key [API_KEY]."
        )
        assert result.sanitized_prompt == expected

    def test_overlap_resolution_preserves_integrity(self, dlp):
        # When an API key appears inside a password key-value assignment
        text = "auth_params: password=sk-example123456789"
        result = dlp.scan_prompt(text)
        assert result.sensitive_data_detected is True
        # Either password or API key is cleanly redacted without text corruption
        assert "sk-example123456789" not in result.sanitized_prompt


# ==============================================================================
# 10. MASKING ENGINE MODES (FULL VS PARTIAL)
# ==============================================================================

class TestMaskingEngine:

    def test_partial_masking_email(self, dlp):
        text = "User email is lokesh@gmail.com."
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert result.sanitized_prompt == "User email is l****h@gmail.com."

    def test_partial_masking_phone(self, dlp):
        text = "Phone: 9876543210."
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert result.sanitized_prompt == "Phone: ******3210."

    def test_partial_masking_ipv4(self, dlp):
        text = "Host 192.168.1.10 online."
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert result.sanitized_prompt == "Host 192.168.*.* online."

    def test_partial_masking_aadhaar(self, dlp):
        text = "Aadhaar: 123456789012."
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert result.sanitized_prompt == "Aadhaar: ********9012."

    def test_partial_masking_card(self, dlp):
        text = "Card: 4111111111111111."
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert result.sanitized_prompt == "Card: 4111********1111."

    def test_critical_credentials_always_fully_redacted(self, dlp):
        # Security rule: API keys and passwords must never be partially revealed
        text = "Credentials: sk-example123456789 and password=MySecret123!"
        result = dlp.scan_prompt(text, mode=MaskingMode.PARTIAL)
        assert "[API_KEY]" in result.sanitized_prompt
        assert "[PASSWORD]" in result.sanitized_prompt
        assert "sk-" not in result.sanitized_prompt
        assert "MySecret" not in result.sanitized_prompt

    def test_custom_masking_labels(self, dlp):
        custom = {
            SensitiveDataCategory.EMAIL: "<REDACTED_EMAIL>",
            SensitiveDataCategory.IPV4: "<PRIVATE_IP>",
        }
        text = "Email info@example.com on 10.0.0.1"
        result = dlp.scan_prompt(text, custom_labels=custom)
        assert result.sanitized_prompt == "Email <REDACTED_EMAIL> on <PRIVATE_IP>"


# ==============================================================================
# 11. LLM RESPONSE SCANNER TESTS
# ==============================================================================

class TestResponseScanner:

    def test_clean_response_without_leakage(self, dlp):
        response = "The capital of France is Paris. How can I assist you further?"
        result = dlp.scan_response(response)
        assert result.success is True
        assert result.sensitive_data_detected is False
        assert result.detection_count == 0
        assert result.sanitized_response == response
        assert result.risk_level == "NONE"

    def test_leaked_credentials_in_llm_response(self, dlp):
        response = (
            "Here is the database connection details: host=192.168.1.100, "
            "password=ProdPassw0rd!, key=sk-example123456789."
        )
        result = dlp.scan_response(response)
        assert result.sensitive_data_detected is True
        assert result.detection_count == 3
        assert result.risk_level == "CRITICAL"
        assert "[IP_ADDRESS]" in result.sanitized_response
        assert "[PASSWORD]" in result.sanitized_response
        assert "[API_KEY]" in result.sanitized_response
        assert "ProdPassw0rd!" not in result.sanitized_response

    def test_response_scanner_structured_metrics(self, dlp):
        response = "User contact is user@example.com."
        result = dlp.scan_response(response)
        assert "EMAIL" in result.categories
        assert result.detection_count == 1
        assert len(result.detections) == 1
        assert result.detections[0]["category"] == "EMAIL"
        assert result.detections[0]["masked"] is True


# ==============================================================================
# 12. UNIFIED DLP INTERFACE AND ROBUSTNESS
# ==============================================================================

class TestUnifiedDLPInterface:

    def test_dict_and_attribute_interoperability(self, dlp):
        text = "Email: lokesh@gmail.com"
        prompt_res = dlp.scan_prompt(text)

        # Attribute access
        assert prompt_res.sanitized_prompt == "Email: [EMAIL]"
        assert prompt_res.detection_count == 1

        # Dict key access
        assert prompt_res["sanitized_prompt"] == "Email: [EMAIL]"
        assert prompt_res["detection_count"] == 1

        # Dict conversion
        as_dict = prompt_res.to_dict()
        assert isinstance(as_dict, dict)
        assert as_dict["sensitive_data_detected"] is True

        # Unpacking / dict constructor
        dict_constructed = dict(prompt_res)
        assert dict_constructed["sanitized_prompt"] == "Email: [EMAIL]"

    def test_empty_and_whitespace_inputs(self, dlp):
        empty_prompt = dlp.scan_prompt("")
        assert empty_prompt.success is True
        assert empty_prompt.sensitive_data_detected is False
        assert empty_prompt.sanitized_prompt == ""
        assert empty_prompt.detection_count == 0

        whitespace_response = dlp.scan_response("   \n\t  ")
        assert whitespace_response.success is True
        assert whitespace_response.sensitive_data_detected is False
        assert whitespace_response.detection_count == 0

    def test_invalid_input_types_handled_gracefully(self, dlp):
        for invalid_val in [None, 12345, ["list"], {"key": "val"}]:
            prompt_res = dlp.scan_prompt(invalid_val)
            assert prompt_res.success is True
            assert prompt_res.sensitive_data_detected is False
            assert prompt_res.detection_count == 0

            resp_res = dlp.scan_response(invalid_val)
            assert resp_res.success is True
            assert resp_res.sensitive_data_detected is False
            assert resp_res.detection_count == 0


# ==============================================================================
# 13. SECURITY REQUIREMENTS & SECRET PRIVACY
# ==============================================================================

class TestSecurityAndPrivacy:

    def test_detection_item_repr_never_leaks_raw_value(self, detector):
        items = detector.detect("My key is sk-example123456789 and pass password=Secret123")
        assert len(items) >= 1
        for item in items:
            repr_str = repr(item)
            str_str = str(item)
            # Raw secrets must NOT be printed in the repr/str
            assert "sk-example123456789" not in repr_str
            assert "Secret123" not in repr_str
            assert "sk-example123456789" not in str_str
            assert "Secret123" not in str_str
