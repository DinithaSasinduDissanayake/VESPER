"""FastAPI application entry point for VESPER."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from vesper.api import a_text, b_survival
from vesper.api.a_text import router as a_text_router
from vesper.api.b_survival import router as b_survival_router
from vesper.api.c_graph import router as c_graph_router
from vesper.api.knapsack import router as knapsack_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    a_text.warm_up()  # load the A model in the background; startup does not wait
    b_survival.warm_up()  # fit the B model in the background (about 15 s)
    yield


app = FastAPI(title="VESPER API", version="0.1.0", lifespan=lifespan)
app.include_router(knapsack_router)
app.include_router(c_graph_router)
app.include_router(a_text_router)
app.include_router(b_survival_router)


@app.get("/api/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
