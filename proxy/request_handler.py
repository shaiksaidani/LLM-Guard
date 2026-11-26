
import uuid

from proxy.llm_client import generate_response
from proxy.response_handler import process_response


def process_request(prompt, user_id):
    """
    Process a request with unique ID tracking
    and exception handling.
    """

    request_id = "REQ-" + str(uuid.uuid4())

    try:
        llm_result = generate_response(prompt)

        response_result = process_response(
            llm_result,
            request_id
        )

        result = {
            "request_id": "REQ-generated-unique-id",
            "user_id": "saidani",
            "prompt":"Explain cybersecurity",
            "status": "success",
            "llm_response": "This is a mock LLM response for: Explain cybersecurity",
            "model": "mock-llm"
}

        return result

    except Exception:
        return {
            "request_id": request_id,
            "user_id": user_id,
            "status": "error",
            "message": "An internal error occurred while processing the request."
        }




