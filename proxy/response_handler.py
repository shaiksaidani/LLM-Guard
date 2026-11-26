
def process_response(llm_result, request_id):
    """
    Validate and format the response received
    from the LLM client.
    """

    if not isinstance(llm_result, dict):
        return {
            "request_id": request_id,
            "status": "error",
            "message": "Invalid response from LLM"
        }

    response_text = llm_result.get("response")

    if not isinstance(response_text, str) or not response_text.strip():
        return {
            "request_id": request_id,
            "status": "error",
            "message": "LLM response content is missing"
        }

    return {
        "request_id": request_id,
        "status": "success",
        "model": llm_result.get("model", "unknown"),
        "response": response_text
    }

