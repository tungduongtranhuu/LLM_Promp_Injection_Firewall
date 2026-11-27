from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(title="RAG Shield")

app.include_router(router)


@app.get("/")
async def root() -> dict:
    return {"message": "RAG Shield running"}
