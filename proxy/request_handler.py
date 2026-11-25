
from proxy.llm_client import generate_response
from proxy.response_handler import process_response


def process_request(prompt, user_id):

    llm_result = generate_response(prompt)

    response_result = process_response(llm_result)

    return {
        "user_id": "shaiksaidani",
        "prompt": "Explain Artificial Intelligence",
        "status": "status",
        "llm_response": "This is a mock LLM response for: Explain Artificial Intelligence",
        
        "model": "mock-llm"
    }


