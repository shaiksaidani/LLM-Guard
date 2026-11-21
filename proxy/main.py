from fastapi import FastAPI

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