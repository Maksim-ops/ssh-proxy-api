from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.crud.routes import actions_router, projects_router, proxies_router, servers_router, teams_router, tokens_router, users_router
from app.api.errors import make_error_body
from app.api.routes_admin import router as admin_router
from app.api.routes_auth import router as auth_router
from app.api.routes_exec import router as exec_router
from app.api.routes_servers import router as scoped_servers_router
from app.api.routes_sessions import router as sessions_router
from app.bootstrap.ssh_import import maybe_import_ssh_config_servers
from app.config import CONFIG, SETTINGS, reload_config
from app.db.repositories import ensure_seed_data
from app.db.session import init_db, wait_for_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    reload_config()
    wait_for_db()
    init_db()
    ensure_seed_data()
    maybe_import_ssh_config_servers()
    yield


app = FastAPI(title="core-api", version="1.2.0", lifespan=lifespan)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    return JSONResponse(status_code=exc.status_code, content=make_error_body(error="http_error", message=str(exc.detail)))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content=make_error_body(error="validation_error", message=str(exc)))


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "core-api",
        "version": "1.2.0",
        "config": SETTINGS.config_path,
        "servers": list((CONFIG.get("servers") or {}).keys()),
        "auth": "password+session",
        "log_dir": SETTINGS.log_dir,
        "ssh_import_mode": SETTINGS.ssh_import_mode,
    }


app.include_router(auth_router)
app.include_router(exec_router)
app.include_router(sessions_router)
app.include_router(scoped_servers_router)
app.include_router(users_router)
app.include_router(teams_router)
app.include_router(projects_router)
app.include_router(proxies_router)
app.include_router(servers_router)
app.include_router(actions_router)
app.include_router(tokens_router)
app.include_router(admin_router)
