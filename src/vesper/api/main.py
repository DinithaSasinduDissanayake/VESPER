"""FastAPI application entry point for VESPER."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from vesper.api import a_text
from vesper.api.a_text import router as a_text_router
from vesper.api.c_graph import router as c_graph_router
from vesper.api.knapsack import router as knapsack_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    a_text.warm_up()  # load the A model in the background; startup does not wait
    yield


app = FastAPI(title="VESPER API", version="0.1.0", lifespan=lifespan)
app.include_router(knapsack_router)
app.include_router(c_graph_router)
app.include_router(a_text_router)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    """FastAPI's default 422 handler, but raw non-UTF-8 body bytes no longer crash it."""

    errors = jsonable_encoder(
        error.errors(), custom_encoder={bytes: lambda value: value.decode("utf-8", "replace")}
    )
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/api/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
