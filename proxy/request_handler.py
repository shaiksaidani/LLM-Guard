
import uuid

from proxy.llm_client import generate_response
from proxy.response_handler import process_response
from proxy.security_hooks import inspect_prompt, inspect_response


def process_request(prompt, user_id):
    """
    Process requests with security integration hooks,
    request ID tracking and error handling.
    """

    request_id = "REQ-" + str(uuid.uuid4())

    try:
        # Step 1: Inspect incoming prompt
        prompt_check = inspect_prompt(prompt, user_id)

        if not prompt_check["allowed"]:
            return {
                "request_id": request_id,
                "user_id": user_id,
                "status": "blocked",
                "message": prompt_check.get("reason")
            }

        # Step 2: Send approved prompt to mock LLM
        llm_result = generate_response(prompt_check["content"])

        # Step 3: Process LLM response
        response_result = process_response(
            llm_result,
            request_id
        )

        if response_result["status"] != "success":
            return {
                "request_id": request_id,
                "user_id": user_id,
                "status": "error",
                "message": response_result.get("message", "Response processing failed")
            }

        # Step 4: Inspect outgoing response
        response_check = inspect_response(
            response_result["response"],
            user_id
        )

        if not response_check["allowed"]:
            return {
                "request_id": request_id,
                "user_id": user_id,
                "status": "blocked",
                "message": response_check.get("reason")
            }

        # Step 5: Return final response
        return {
            "request_id": "REQ-generated-unique-id",
            "user_id": "saidani",
            "status": "success",
            "llm_response": "This is a mock LLM response for: Explain cybersecurity",
            "model": "mock-llm"
        }

    except Exception:
        return {
            "request_id": request_id,
            "user_id": user_id,
            "status": "error",
            "message": "An internal error occurred while processing the request."
        }







