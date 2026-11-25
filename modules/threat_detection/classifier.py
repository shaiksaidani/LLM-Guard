
from dataclasses import dataclass

import numpy as np
import onnxruntime as ort

from huggingface_hub import hf_hub_download
from transformers import AutoTokenizer


MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


@dataclass
class NLPClassificationResult:
    label: str
    confidence: float
    safe_probability: float
    injection_probability: float
    is_injection: bool


class PromptNLPClassifier:

    def __init__(self, threshold=0.5):

        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0 and 1.")

        self.threshold = threshold

        # Load the model tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_ID,
            subfolder="onnx"
        )

        # Locate the downloaded ONNX model
        model_path = hf_hub_download(
            repo_id=MODEL_ID,
            filename="onnx/model.onnx"
        )

        # Load model using CPU
        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"]
        )

        self.input_names = {
            item.name for item in self.session.get_inputs()
        }

    def classify(self, prompt: str) -> NLPClassificationResult:

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        # Convert prompt into model inputs
        encoded = self.tokenizer(
            prompt,
            return_tensors="np",
            truncation=True,
            max_length=512,
            padding=True
        )

        # Pass only inputs required by ONNX model
        model_inputs = {
            name: encoded[name].astype(np.int64)
            for name in self.input_names
        }

        # Run NLP inference
        logits = self.session.run(
            ["logits"],
            model_inputs
        )[0][0]

        # Convert logits into probabilities
        exp_scores = np.exp(logits - np.max(logits))
        probabilities = exp_scores / np.sum(exp_scores)

        # Model configuration: 0 = SAFE, 1 = INJECTION
        safe_probability = float(probabilities[0])
        injection_probability = float(probabilities[1])

        is_injection = injection_probability >= self.threshold

        return NLPClassificationResult(
            label="INJECTION" if is_injection else "SAFE",
            confidence=max(safe_probability, injection_probability),
            safe_probability=safe_probability,
            injection_probability=injection_probability,
            is_injection=is_injection
        )
