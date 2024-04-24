from fastapi import Depends, FastAPI
from app.routers import auth

app = FastAPI()

app.include_router(auth.router)


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Hello World!"}
