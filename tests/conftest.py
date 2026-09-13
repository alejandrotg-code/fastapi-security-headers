"""Pytest configuration and shared fixtures for fastapi-security-headers."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_security_headers import SecurityHeadersConfig, SecurityHeadersMiddleware


@pytest.fixture
def create_app():
    """Factory fixture to create a FastAPI application wrapped with SecurityHeadersMiddleware."""

    def _factory(config: SecurityHeadersConfig = None, override: bool = False) -> FastAPI:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, config=config, override=override)

        @app.get("/")
        async def root():
            return {"message": "secure-hello"}

        @app.get("/custom-frame")
        async def custom_frame():
            from fastapi.responses import JSONResponse

            return JSONResponse(
                content={"message": "with-frame"},
                headers={"x-frame-options": "SAMEORIGIN"},
            )

        return app

    return _factory


@pytest.fixture
def client(create_app):
    """Default TestClient using default SecurityHeadersConfig."""
    app = create_app()
    return TestClient(app)
