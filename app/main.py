"""Точка входа FastAPI-приложения."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.auth import LoginRequired, ensure_initial_admin
from app.config import BASE_DIR, get_settings
from app.db import create_all, session_scope
from app.security.middleware import CSRFMiddleware, SecurityHeadersMiddleware
from app.templating import render

log = logging.getLogger("app")


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("fontTools", "weasyprint", "httpx", "httpcore", "apscheduler.executors.default"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _configure_logging()
    settings = get_settings()
    for d in (settings.data_dir, settings.reports_dir, settings.scans_dir):
        d.mkdir(parents=True, exist_ok=True)
    create_all()
    with session_scope() as db:
        msg = ensure_initial_admin(db)
        if msg:
            log.warning(msg)
        from app.targets_service import import_targets_file

        res = import_targets_file(db)
        if res is not None:
            log.info("Импорт targets.yaml: создано %s, обновлено %s, ошибок %s", res.created, res.updated, len(res.errors))
            for err in res.errors:
                log.warning("targets.yaml: %s", err)

    from app.scanner.engine import scan_manager

    scan_manager.start()
    from app.scheduler import start_scheduler, stop_scheduler

    start_scheduler()
    try:
        yield
    finally:
        stop_scheduler()
        scan_manager.shutdown()


def create_app() -> FastAPI:
    app = FastAPI(
        title=get_settings().app_name,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    from app.routers import (
        assets,
        audit_log,
        auth,
        dashboard,
        findings,
        reports,
        scans,
        schedules,
        settings_page,
        targets,
        users,
    )

    for module in (
        auth,
        dashboard,
        targets,
        scans,
        assets,
        findings,
        reports,
        schedules,
        settings_page,
        users,
        audit_log,
    ):
        app.include_router(module.router)

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, _exc: LoginRequired) -> Response:
        nxt = request.url.path if request.method == "GET" else "/"
        return RedirectResponse(f"/login?next={nxt}", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> Response:
        if request.headers.get("hx-request") or request.url.path.startswith("/api/"):
            return PlainTextResponse(str(exc.detail), status_code=exc.status_code, headers=exc.headers)
        titles = {403: "Доступ запрещён", 404: "Не найдено", 401: "Требуется вход"}
        return render(
            request,
            "error.html",
            {"code": exc.status_code, "title": titles.get(exc.status_code, "Ошибка"), "message": exc.detail},
            status_code=exc.status_code,
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    return app


app = create_app()
