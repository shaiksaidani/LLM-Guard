
from proxy.llm_client import generate_response


def process_request(prompt, user_id):
    """
    Process a validated request and get a response
    from the mock LLM client.
    """

    llm_result = generate_response(prompt)

    result = {
        "user_id": "shaiksaidani",
        "prompt": "Explain Artificial Intelligence",
        "status": "processed",
        "llm_response": llm_result["response"],
        "model": llm_result["model"]
    }

    return result
