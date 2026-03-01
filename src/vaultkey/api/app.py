from fastapi import FastAPI

from vaultkey.shared.logging import setup_logging


def create_app() -> FastAPI:
    setup_logging()
    app = FastAPI(title="VaultKey", version="0.1.0")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
