from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class Health:
    ok: bool
    reason: str | None = None


def check_local_health(max_swap_bytes: int, max_mem_percent: float) -> Health:
    swap = psutil.swap_memory()
    if swap.used > max_swap_bytes:
        return Health(False, f"swap_used={swap.used}")

    vm = psutil.virtual_memory()
    if vm.percent >= max_mem_percent:
        return Health(False, f"mem_percent={vm.percent}")

    return Health(True, None)
