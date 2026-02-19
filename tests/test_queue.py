import asyncio

from src.router.queue.heavy_slot import HeavySlot


async def _run_slot_once(slot: HeavySlot):
    async with slot:
        return True


def test_heavy_slot_allows_entry():
    result = asyncio.run(_run_slot_once(HeavySlot(1)))
    assert result is True
