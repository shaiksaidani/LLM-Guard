from pydantic import BaseModel, Field, field_validator


class ChatRequest(BaseModel):

    prompt: str = Field(
        min_length=1,
        max_length=4000
    )

    user_id: str = Field(
        default="anonymous",
        min_length=1,
        max_length=100
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("Prompt cannot be empty")

        return value

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("User ID cannot be empty")

        return value