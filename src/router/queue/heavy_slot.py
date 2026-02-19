import asyncio


class HeavySlot:
    def __init__(self, n: int = 1):
        self._sem = asyncio.Semaphore(n)

    async def __aenter__(self):
        await self._sem.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._sem.release()
