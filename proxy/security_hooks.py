
def inspect_prompt(prompt, user_id):
    """
    Security interface for incoming prompt inspection.

    Later, this function will connect with AI threat
    detection and firewall modules.
    """

    return {
        "allowed": True,
        "content": prompt,
        "reason": None
    }


def inspect_response(response, user_id):
    """
    Security interface for outgoing response inspection.

    Later, this function will connect with the DLP
    response scanner.
    """

    return {
        "allowed": True,
        "content": response,
        "reason": None
    }
