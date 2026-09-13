"""Pure ASGI Middleware for injecting HTTP security headers.

High-performance, zero-copy architecture that operates directly on ASGI message streams
without buffering response bodies or imposing memory overhead.
"""

from typing import Any, Awaitable, Callable, List, MutableMapping, Optional, Set, Tuple

from .config import SecurityHeadersConfig

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class SecurityHeadersMiddleware:
    """Pure ASGI middleware that injects pre-compiled OWASP security headers.

    Compatible with FastAPI, Starlette, and any ASGI 3 framework.

    Example:
        ```python
        from fastapi import FastAPI
        from fastapi_security_headers import SecurityHeadersMiddleware, Presets

        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, config=Presets.api())
        ```

    Attributes:
        app: The inner ASGI application.
        config: SecurityHeadersConfig instance. Defaults to Presets.default().
        override: If True, overrides existing headers from route responses.
                  If False (default), respects headers explicitly set by routes.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: Optional[SecurityHeadersConfig] = None,
        override: bool = False,
    ) -> None:
        self.app = app
        self.config: SecurityHeadersConfig = config or SecurityHeadersConfig()
        self.override: bool = override
        # Pre-compile headers once at startup for zero-overhead per-request execution
        self._compiled_headers: List[Tuple[bytes, bytes]] = self.config.compile_headers()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only process HTTP requests; pass WebSockets and lifespan events untouched
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message.get("type") == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers", []))

                if self.override:
                    # Remove any matching headers before appending our pre-compiled headers
                    compiled_keys: Set[bytes] = {k for k, _ in self._compiled_headers}
                    raw_headers = [
                        (k, v) for k, v in raw_headers if k.lower() not in compiled_keys
                    ]
                    raw_headers.extend(self._compiled_headers)
                else:
                    # Only append headers that haven't been explicitly defined by the route
                    existing_keys: Set[bytes] = {k.lower() for k, _ in raw_headers}
                    for header_name, header_value in self._compiled_headers:
                        if header_name not in existing_keys:
                            raw_headers.append((header_name, header_value))

                message["headers"] = raw_headers

            await send(message)

        await self.app(scope, receive, send_wrapper)
