from unittest.mock import patch

from src.router.health.local_health import check_local_health


@patch("src.router.health.local_health.psutil.virtual_memory")
@patch("src.router.health.local_health.psutil.swap_memory")
def test_health_fails_on_swap(mock_swap, mock_vm):
    mock_swap.return_value.used = 1024
    mock_vm.return_value.percent = 10.0
    health = check_local_health(max_swap_bytes=0, max_mem_percent=92.0)
    assert health.ok is False
    assert "swap_used" in (health.reason or "")


@patch("src.router.health.local_health.psutil.virtual_memory")
@patch("src.router.health.local_health.psutil.swap_memory")
def test_health_fails_on_memory(mock_swap, mock_vm):
    mock_swap.return_value.used = 0
    mock_vm.return_value.percent = 95.0
    health = check_local_health(max_swap_bytes=0, max_mem_percent=92.0)
    assert health.ok is False
    assert "mem_percent" in (health.reason or "")
