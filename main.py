from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine
from routers.cases import router as cases_router
from routers.investigators import router as investigators_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifecycle manager:
    Ensures all database tables exist on startup.
    """
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="E2EE Whistleblower Zero-Knowledge API",
    description=(
        "Production-ready Zero-Knowledge blind storage backend for anonymous whistleblower submissions. "
        "The server never has access to plaintext messages, secret keys, or raw access tokens."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for web frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(investigators_router)
app.include_router(cases_router)


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """
    Health check endpoint for container orchestrators and monitoring.
    """
    return {"status": "healthy", "service": "e2ee-whistleblower-backend"}


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "message": "E2EE Whistleblower Zero-Knowledge Backend API",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
