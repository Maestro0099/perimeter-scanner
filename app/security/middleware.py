"""Заголовки безопасности и защита от CSRF (double-submit cookie + проверка Origin)."""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

CSRF_COOKIE = "ps_csrf"
CSRF_HEADER = "x-csrf-token"
CSRF_FIELD = "csrf_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if get_settings().cookie_secure:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if not request.url.path.startswith("/static/"):
            h.setdefault("Cache-Control", "no-store")
        return response


class CSRFMiddleware:
    """Чистое ASGI-middleware: тело запроса буферизуется и передаётся дальше без потерь."""

    MAX_BODY = 5 * 1024 * 1024

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        cookie_token = request.cookies.get(CSRF_COOKIE)
        valid_cookie = bool(cookie_token and 32 <= len(cookie_token) <= 128)
        token = cookie_token if valid_cookie else secrets.token_urlsafe(32)
        scope.setdefault("state", {})["csrf_token"] = token

        if request.method not in SAFE_METHODS:
            if not self._origin_ok(request):
                await PlainTextResponse("Запрос отклонён: недопустимый Origin", status_code=403)(scope, receive, send)
                return
            body = b""
            more = True
            while more:
                message = await receive()
                body += message.get("body", b"")
                more = message.get("more_body", False)
                if len(body) > self.MAX_BODY:
                    await PlainTextResponse("Слишком большой запрос", status_code=413)(scope, receive, send)
                    return

            async def replay() -> Message:
                return {"type": "http.request", "body": body, "more_body": False}

            sent = request.headers.get(CSRF_HEADER)
            if not sent:
                ctype = request.headers.get("content-type", "")
                if ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
                    try:
                        form = await Request(scope, replay).form()
                        value = form.get(CSRF_FIELD)
                        sent = value if isinstance(value, str) else None
                    except Exception:  # noqa: BLE001
                        sent = None
            if not valid_cookie or not sent or not hmac.compare_digest(str(cookie_token), sent):
                await PlainTextResponse(
                    "Запрос отклонён: недействительный CSRF-токен. Обновите страницу.", status_code=403
                )(scope, receive, send)
                return
            receive = replay

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and not valid_cookie:
                headers = MutableHeaders(scope=message)
                cookie = f"{CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"
                if get_settings().cookie_secure:
                    cookie += "; Secure"
                headers.append("set-cookie", cookie)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    @staticmethod
    def _origin_ok(request: Request) -> bool:
        origin = request.headers.get("origin") or request.headers.get("referer")
        if not origin:
            return True  # старые клиенты; токен всё равно проверяется
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        return urlsplit(origin).netloc == host
