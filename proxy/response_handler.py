
def process_response(llm_result):
    """
    Validate and format the response received
    from the mock LLM client.
    """

    if not llm_result:
        return {
            "status": "error",
            "message": "Empty response from LLM"
        }

    response_text = llm_result.get("response", "")

    if not response_text:
        return {
            "status": "error",
            "message": "LLM response is missing"
        }

    return {
        "status": "success",
        "model": llm_result.get("model", "unknown"),
        "response": response_text
    }
