"""FastAPI application entry point for VESPER."""

from fastapi import FastAPI

from vesper.api.a_text import router as a_text_router
from vesper.api.c_graph import router as c_graph_router
from vesper.api.knapsack import router as knapsack_router

app = FastAPI(title="VESPER API", version="0.1.0")
app.include_router(knapsack_router)
app.include_router(c_graph_router)
app.include_router(a_text_router)


@app.get("/api/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
