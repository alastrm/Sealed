from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from database import Base, engine
from logging_config import get_anonymized_uvicorn_log_config, setup_anonymized_logging
from rate_limiter import limiter
from routers.cases import router as cases_router
from routers.investigators import router as investigators_router
from routers.investigator_sessions import router as investigator_sessions_router
from investigator_auth import allowed_origins
from migrate_v2 import require_schema
from migrate_m4 import require_m4_schema
from sqlalchemy import inspect
from routers.reporter_authentication import router as reporter_auth_router
from fastapi.exceptions import RequestValidationError

# Setup anonymized logging as early as possible
setup_anonymized_logging()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifecycle manager:
    Ensures all database tables exist on startup and logging is anonymized.
    """
    setup_anonymized_logging()
    if 'cases' in inspect(engine).get_table_names():
        require_m4_schema(engine)
    else:
        Base.metadata.create_all(bind=engine)
    require_schema(engine)
    yield


app = FastAPI(
    title="Sealed local encrypted reporting API",
    description=(
        "Local portfolio reporting workspace with encrypted payloads, investigator sessions, "
        "and v2 message signatures. See CRYPTOGRAPHIC_AUTHENTICITY.md for trust boundaries and limitations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Connect slowapi Limiter
app.state.limiter = limiter


def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    retry_after = getattr(exc, "retry_after", 60)
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
        headers={"Retry-After": str(retry_after)},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)

# Enable CORS for web frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def private_investigator_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["Cache-Control"] = "no-store"
    return response

# Include API Routers
app.include_router(investigators_router)
app.include_router(investigator_sessions_router)
app.include_router(cases_router)
app.include_router(reporter_auth_router)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, error: RequestValidationError):
    # Pydantic's default response includes rejected input values. Authentication
    # proofs and case credentials must not be reflected in error payloads.
    return JSONResponse(status_code=422, content={'detail': 'Request validation failed.'})


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
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_config=get_anonymized_uvicorn_log_config(),
    )
