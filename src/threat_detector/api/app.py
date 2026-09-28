import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from threat_detector.api.routes import router
from threat_detector.persistence.schema import connect, initialize_schema


DEFAULT_DATABASE_PATH = "threat_detector.sqlite3"
DATABASE_ENVIRONMENT_VARIABLE = "THREAT_DETECTOR_DATABASE"


def create_app(database_path: str | Path | None = None) -> FastAPI:
    selected_path = str(
        database_path
        or os.environ.get(DATABASE_ENVIRONMENT_VARIABLE, DEFAULT_DATABASE_PATH)
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        connection = connect(selected_path)
        try:
            initialize_schema(connection)
        finally:
            connection.close()
        yield

    application = FastAPI(title="Threat Detector Investigation API", lifespan=lifespan)
    application.state.database_path = selected_path
    application.include_router(router)

    @application.exception_handler(sqlite3.Error)
    async def database_error_handler(_: Request, __: sqlite3.Error) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return application


app = create_app()