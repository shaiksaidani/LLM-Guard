
def generate_response(prompt):
    """
    Generate a mock response for the given prompt.
    This simulates an LLM API response.
    """

    response = {
        "response": "This is a mock LLM response for: " + prompt,
        "model": "mock-llm",
        "status": "success"
    }

    return response
