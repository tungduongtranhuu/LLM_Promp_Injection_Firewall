from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(title="LLM Firewall")

app.include_router(router)


@app.get("/")
async def root():
    return {"message": "LLM Firewall running"}

