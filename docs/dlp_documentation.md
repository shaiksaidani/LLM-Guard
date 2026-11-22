# Data Loss Prevention (DLP) Module – LLM-Guard

**Project**: LLM-Guard – Generative AI Prompt Firewall  
**Developer**: Lokesh  
**Assigned Module**: Data Loss Prevention (DLP)  
**Development Phase**: Week 1  
**Status**: Completed & Verified  

---

## 1. Executive Summary & What is DLP?

**Data Loss Prevention (DLP)** is an essential cybersecurity mechanism designed to detect, monitor, and prevent unauthorized transmission, exfiltration, or exposure of sensitive data—such as Personally Identifiable Information (PII), financial records, intellectual property, and system credentials.

In modern cloud and enterprise software architectures, DLP acts as an automated boundary guardian, continuously analyzing data payloads against predefined security policies, regulatory frameworks (e.g., GDPR, HIPAA, PCI-DSS, and India's Digital Personal Data Protection Act - DPDP), and pattern heuristics.

---

## 2. Why DLP is Critical in Generative AI Applications

Large Language Models (LLMs) present unique security and privacy challenges not addressed by traditional web application firewalls:

1. **Inadvertent Data Leakage to Third-Party Providers**: Prompts sent to external AI providers (OpenAI, Anthropic, Google) may be retained for model fine-tuning, logged in telemetry pipelines, or accessible to support staff.
2. **Mitigating OWASP LLM06 (Sensitive Information Disclosure)**: LLMs can inadvertently hallucinate, memorize, or mirror training data, outputting sensitive customer credentials, database secrets, or PII in responses.
3. **Data Exfiltration via Prompt Injection**: Indirect prompt injection attacks attempt to trick LLMs into summarizing or exfiltrating confidential internal documents into user-visible chat sessions.
4. **Regulatory and Legal Compliance**: Frameworks such as DPDP (India) and GDPR (EU) impose severe penalties on organizations that process or transmit unmasked personal identifiers without consent.

The **LLM-Guard DLP module** provides **bidirectional protection**:
- **Ingress (Incoming Prompt Protection)**: Intercepts and masks user-supplied PII and secrets *before* they reach the model.
- **Egress (Outgoing Response Protection)**: Scans generated LLM outputs to detect and redact sensitive system infrastructure details, passwords, or data leaks before reaching the end user.

---

## 3. High-Level DLP Architecture

The DLP module is designed as an independent, decoupled security engine that requires zero external network calls or LLM connections.

```mermaid
flowchart TD
    subgraph Client Application
        U["End User / Client"]
    end

    subgraph LLM-Guard Gateway
        FP["FastAPI Proxy (Saidani)"]
        
        subgraph DLP Module (Lokesh)
            DLP_Facade["DLP Facade (modules.dlp.DLP)"]
            CFG["DLPConfig (modules.dlp.config)"]
            DET["DLPDetector (modules.dlp.detector)"]
            MASK["DLPMasker (modules.dlp.masker)"]
            RESP["DLPResponseScanner (modules.dlp.response_scanner)"]
        end
        
        FW["Firewall & Threat Detection"]
    end

    subgraph External Provider
        LLM["Generative LLM (e.g., OpenAI / Gemini)"]
    end

    U -->|"1. Raw User Prompt"| FP
    FP -->|"2. scan_prompt()"| DLP_Facade
    DLP_Facade --> DET
    DET -->|"Detections & Spans"| MASK
    MASK -->|"3. Sanitized Prompt"| FP
    FP -->|"4. Filtered Prompt"| FW
    FW -->|"5. Safe Prompt"| LLM
    LLM -->|"6. Generated Response"| FP
    FP -->|"7. scan_response()"| RESP
    RESP --> DET
    RESP --> MASK
    RESP -->|"8. Sanitized Response + Security Report"| FP
    FP -->|"9. Safe Response"| U
```

---

## 4. Supported Sensitive Data Categories

The DLP engine supports 8 sensitive data categories with zero-dependency native validation algorithms:

| Category Code | Description | Detection Strategy | Validation / Heuristic | Default Mask |
| :--- | :--- | :--- | :--- | :--- |
| `EMAIL` | Standard & Corporate Email Addresses | RFC 5322 regex + domain length bounds | TLD format, local length check | `[EMAIL]` |
| `PHONE_IN` | Indian Mobile Numbers (10 digits) | Starts with 6, 7, 8, 9; optional `+91`, `91`, `0` | Boundary lookaround & length check | `[PHONE]` |
| `PHONE_INTL` | International Phone Numbers | ITU-T E.164 candidate format | 7 to 15 digit range verification | `[PHONE]` |
| `IPV4` | IPv4 Addresses | 4 octets (0-255) | Octet boundary check (avoids version numbers) | `[IP_ADDRESS]` |
| `API_KEY` | Developer & Cloud API Keys | Known provider prefixes & high-entropy tokens | Shannon Entropy $\ge 3.5$, regex | `[API_KEY]` |
| `AADHAAR` | Indian 12-Digit Identity Candidates | 12 digits, spaced or continuous, starts 1-9 | Optional Verhoeff Checksum | `[AADHAAR]` |
| `CARD` | Credit / Debit Card Candidates | 13 to 19 digits (Visa, MC, Amex, RuPay) | **Luhn Algorithm (Mod 10)** check | `[CARD]` |
| `PASSWORD_KV`| Passwords in explicit assignments | Parameter key-value recognition (`password=...`) | Value isolation & quotation stripping | `[PASSWORD]` |

> [!NOTE]
> **Candidate Detection vs. Identity Verification**: In accordance with security engineering best practices, detection identifies *candidate patterns* and mathematical validity (e.g., Luhn check for cards, Verhoeff for Aadhaar). The system explicitly disclaims claiming whether an entity represents an active bank account or verified identity.

---

## 5. Detection Methodology (`modules/dlp/detector.py`)

### 5.1 Checksum & Heuristic Validators
- **Luhn Algorithm (`validate_luhn`)**: Validates candidate card numbers against ISO/IEC 7812 specifications. Eliminates false positives from arbitrary 16-digit sequences (e.g., order tracking numbers).
- **Verhoeff Checksum (`validate_verhoeff`)**: Implements the dihedral group $D_5$ algorithm utilized by UIDAI for Indian Aadhaar validation.
- **Shannon Entropy (`calculate_shannon_entropy`)**: Measures the information density of candidate API tokens:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Ensures strings with low entropy (e.g., repeated words) are not misclassified as cryptographic keys.

### 5.2 False-Positive Mitigation
- **Version Number Rejection**: Software versions such as `1.2.3.4.5` are prevented from matching the IPv4 detector using lookarounds `(?<!\d\.)` and `(?!\.\d)`.
- **Code & Syntax Isolation**: Method invocations such as `client.email()` or document names like `file.pdf` are rejected by requiring strict RFC local-part and domain TLD rules.

### 5.3 Overlap Resolution & Conflict Arbitration
When a single string contains overlapping matches (e.g., an API key passed inside a password assignment `password=sk-example...`), the `_resolve_overlaps()` algorithm:
1. Sorts candidate detections by ascending start position and descending match span.
2. Compares contiguous matches.
3. Prioritizes critical security categories (`API_KEY`, `PASSWORD_KV`, `CARD`) over generic categories.
4. Ensures all output detection spans are strictly disjoint: $[start_i, end_i) \cap [start_j, end_j) = \emptyset$.

---

## 6. Masking Methodology (`modules/dlp/masker.py`)

### 6.1 Safe Reverse-Index Replacement
Text replacement using naive `.replace()` calls is dangerous because:
- Identical substrings occurring elsewhere in the prompt might be replaced unintentionally.
- Replacing earlier occurrences alters character offsets for later detections.

The DLP Masker sorts detections in **descending order of their start index** (from right to left). Each replacement is applied as an exact slice:
```python
sanitized = sanitized[:item.start] + replacement + sanitized[item.end:]
```
This guarantees that character index shifts never corrupt preceding match coordinates.

### 6.2 Masking Modes
1. **Full Redaction (`MaskingMode.FULL`)**:
   Replaces the entire sensitive span with the category placeholder label (e.g., `[EMAIL]`, `[PHONE]`, `[API_KEY]`).
2. **Partial Masking (`MaskingMode.PARTIAL`)**:
   Provides contextual debugging or user-friendly confirmation while obscuring the data:
   - **Email**: `lokesh@gmail.com` $\rightarrow$ `l****h@gmail.com`
   - **Phone**: `9876543210` $\rightarrow$ `******3210`
   - **IPv4**: `192.168.1.10` $\rightarrow$ `192.168.*.*`
   - **Aadhaar**: `123456789012` $\rightarrow$ `********9012`
   - **Credit Card**: `4111111111111111` $\rightarrow$ `4111********1111`

> [!IMPORTANT]
> **Strict Security Rule for Credentials**: In partial masking mode, `API_KEY` and `PASSWORD_KV` are **always fully redacted**. Partial disclosure of secret tokens aids brute-force attacks and is strictly prohibited.

---

## 7. Outgoing LLM Response Scanning (`modules/dlp/response_scanner.py`)

The response scanner inspects generated LLM outputs for inadvertent data leakage. It outputs a `ResponseScanReport` featuring:
- Sanitized response string.
- Sensitive data boolean flag.
- Unique categories detected.
- Overall risk rating:
  - `CRITICAL`: Leaked API keys or passwords.
  - `HIGH`: Credit cards or national IDs.
  - `MEDIUM`: Emails or phone numbers.
  - `LOW`: IP addresses.
  - `NONE`: Clean response.
- ISO 8601 UTC timestamp and sanitized preview metadata.

---

## 8. Unified Interface (`modules/dlp/__init__.py`)

The module exposes a single, intuitive class: `DLP`.

```python
from modules.dlp import DLP

# Initialize DLP Engine
dlp = DLP()

# 1. Incoming prompt scanning
prompt_result = dlp.scan_prompt("My email is lokesh@gmail.com and server is 192.168.1.10")
print(prompt_result.sanitized_prompt)
# Output: "My email is [EMAIL] and server is [IP_ADDRESS]"

# 2. Outgoing response scanning
response_result = dlp.scan_response("Database connection established: password=SecretPass!")
print(response_result.sanitized_response)
# Output: "Database connection established: password=[PASSWORD]"
print(response_result.risk_level)
# Output: "CRITICAL"
```

### Dual Access Compatibility
All result models (`PromptScanReport` and `ResponseScanReport`) support:
- **Attribute Access**: `res.sanitized_prompt`
- **Dictionary Key Access**: `res["sanitized_prompt"]`
- **Native Dict Conversion**: `res.to_dict()` or `dict(res)`

---

## 9. Integration Guide for Saidani's FastAPI Backend

The DLP module can be integrated into FastAPI as a route dependency, an endpoint utility, or HTTP middleware.

### 9.1 Middleware Integration Example
```python
from fastapi import FastAPI, Request
from modules.dlp import DLP

app = FastAPI(title="LLM-Guard Proxy")
dlp = DLP()

@app.middleware("http")
async def dlp_security_middleware(request: Request, call_next):
    # Only scan proxy generation endpoints
    if request.url.path == "/v1/chat/completions" and request.method == "POST":
        body = await request.json()
        raw_prompt = body.get("prompt", "")
        
        # 1. Scan incoming prompt
        prompt_scan = dlp.scan_prompt(raw_prompt)
        body["prompt"] = prompt_scan["sanitized_prompt"]
        
        # Forward sanitized payload downstream
        # ...
    response = await call_next(request)
    return response
```

### 9.2 Route Endpoint Integration Example
```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from modules.dlp import DLP

app = FastAPI()
dlp = DLP()

class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    reply: str
    security_metadata: dict

@app.post("/generate", response_model=ChatResponse)
async def generate_response(req: ChatRequest):
    # Step 1: Ingress DLP Sanitization
    prompt_report = dlp.scan_prompt(req.prompt)
    safe_prompt = prompt_report.sanitized_prompt

    # Step 2: Send safe_prompt to downstream LLM (Mock / Actual LLM)
    raw_llm_reply = f"Acknowledged request: your email is {prompt_report.sanitized_prompt}"

    # Step 3: Egress DLP Sanitization
    response_report = dlp.scan_response(raw_llm_reply)

    return ChatResponse(
        reply=response_report.sanitized_response,
        security_metadata={
            "prompt_detected": prompt_report.sensitive_data_detected,
            "response_detected": response_report.sensitive_data_detected,
            "response_risk": response_report.risk_level
        }
    )
```

---

## 10. Security & Privacy Guarantees

1. **No Raw Secrets in Logs or String Representations**: `DetectionItem.__repr__` and `__str__` mask all sensitive values. Inspecting or logging detection objects will never expose credentials.
2. **Synthetic Test Data Only**: The test suite strictly uses synthetic values (e.g., standard Visa 4111-1111-1111-1111 test cards, example sk- keys, dummy phone numbers).
3. **Safe Exception Handling**: Internal exceptions during regex or string manipulation are caught gracefully; raw inputs are never propagated in error messages.
4. **Decoupled Architecture**: Operates fully offline without network access or cloud API dependencies.

---

## 11. Testing & Verification

### Running the Test Suite
Execute the test suite using pytest from the repository root:
```bash
pytest tests/test_dlp.py -v
```

### Test Coverage Highlights (42 Tests Passing)
- **Email Detection**: Standard emails, subdomain addresses, punctuation boundaries, code false-positive rejection.
- **Phone Detection**: Indian mobile (+91, 0, hyphenated), international E.164 numbers, invalid prefixes.
- **IPv4 Detection**: Private, public, loopback IPs, version number false positives (`1.2.3.4.5`), invalid octets.
- **Aadhaar Candidates**: Spaced and continuous 12-digit formats, Verhoeff checksum algorithm.
- **Credit Cards**: Synthetic Visa test card, spaced and hyphenated formats, Luhn checksum validation and failure rejection.
- **API Keys**: OpenAI `sk-`, AWS access key, GitHub token, Bearer tokens, private key blocks.
- **Passwords**: Quoted and unquoted key-value assignments.
- **Masking Modes**: Full redaction, partial masking, credential protection override, custom label mapping.
- **Response Scanner**: Clean response verification, credential leakage detection, structured risk metrics.
- **Interface Robustness**: Dictionary and attribute access, empty string, whitespace, non-string invalid types.
- **Privacy Enforcement**: Inspection of `repr()` and `str()` ensuring zero raw credential exposure.

---

## 12. Known Limitations & Roadmap for Week 2+

1. **Presidio NLP Layer**: Current detection relies on high-speed regex and algorithmic checksums. Integrating Microsoft Presidio / Spacy NER in future iterations will improve detection of contextual personal names and physical addresses.
2. **IPv6 Support**: Currently focused on IPv4; IPv6 pattern detection will be added in upcoming network security sprints.
3. **Complex Document Formats**: Scans raw text strings; scanning uploaded binary files (PDFs, DOCX) can be added via document extractors.
