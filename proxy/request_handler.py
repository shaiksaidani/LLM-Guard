
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
        "request_id": request_id,
        "user_id": user_id,
        "prompt": prompt,
        "status": response_result["status"],
        "llm_response": response_result.get(
            "response",
            response_result.get("message", "")
        ),
        "model": response_result.get("model", "unknown")
    }

    return result



