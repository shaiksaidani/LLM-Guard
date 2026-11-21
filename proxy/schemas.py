from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    user_id: str = "anonymous"


class ChatResponse(BaseModel):
    request_id: str
    status: str
    response: str