from  fastapi import FastAPI

from proxy.schemas import ChatRequest

app = FastAPI(
    title="LLM-Guard",
    description="Generative AI Prompt Firewall",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "project": "LLM-Guard",
        "message": "Prompt Firewall Backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/api/v1/validate")
def validate_request(request: ChatRequest):

    return {
        "status": "valid",
        "user_id": "shaiksaidani",
        "prompt_length": 20,
        "message": "Request validation successful"
    }