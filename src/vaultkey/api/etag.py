import hashlib

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class ETagMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if request.method == "GET" and request.url.path.startswith("/v1/secrets"):
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            etag = hashlib.sha256(body).hexdigest()
            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304)
            return Response(
                content=body,
                status_code=response.status_code,
                headers={**dict(response.headers), "etag": etag},
                media_type=response.media_type,
            )
        return response
