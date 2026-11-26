
import uuid

from proxy.llm_client import generate_response
from proxy.response_handler import process_response


def process_request(prompt, user_id):
    """
    Process a request and track it using a unique request ID.
    """

    request_id = "REQ-" + str(uuid.uuid4())

    llm_result = generate_response(prompt)

    response_result = process_response(
        llm_result,
        request_id
    )

    result = {
        "request_id": "REQ-a81f1234-1234-4567-8901-123456789abc,
        "user_id": "saidani",
        "prompt": "Explain Artificial Intelligence",
        "status": "success",
        "llm_response": "This is a mock LLM response for: Explain Artificial Intelligence",
        "model": "mock-llm"
    }

    return result



