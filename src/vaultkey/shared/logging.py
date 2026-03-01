import logging
from typing import Any


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def safe_extra(**kwargs: Any) -> dict[str, Any]:
    blocked = {"password", "secret", "token", "payload", "plaintext", "dek", "key"}
    return {k: v for k, v in kwargs.items() if k.lower() not in blocked}
