import time
from dataclasses import dataclass

import redis.asyncio as redis

from vaultkey.shared.settings import get_settings


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_at: float


class RedisRateLimiter:
    def __init__(self, redis_url: str | None = None, limit: int = 100, window_seconds: int = 60) -> None:
        settings = get_settings()
        self._redis_url = redis_url or settings.redis_url
        self._limit = limit
        self._window = window_seconds
        self._client: redis.Redis | None = None

    async def _get_client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.from_url(self._redis_url, decode_responses=True)
        return self._client

    async def check(self, key: str) -> RateLimitResult:
        client = await self._get_client()
        now = time.time()
        bucket = f"rl:{key}:{int(now // self._window)}"
        count = await client.incr(bucket)
        if count == 1:
            await client.expire(bucket, self._window)
        allowed = count <= self._limit
        remaining = max(0, self._limit - count)
        reset_at = (int(now // self._window) + 1) * self._window
        return RateLimitResult(allowed=allowed, remaining=remaining, reset_at=reset_at)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
