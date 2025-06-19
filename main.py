from fastapi import FastAPI
import uvicorn
from src.api import router

app = FastAPI(docs="/")
app.include_router(router)


@app.get("/hello")
def hello():
    return {"msg": "hi"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
