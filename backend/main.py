"""NetDigno — entry point (legacy compatibility and direct run support)."""
import uvicorn
from app.main import app  # noqa: F401 — export for uvicorn

if __name__ == "__main__":
    from app.core.config import settings
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=False,
    )
