import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    CoreProfileSessionTap,
)


@pytest.mark.asyncio
async def test_stackshot(service_provider: LockdownServiceProvider) -> None:
    """
    Test getting stackshot.
    """
    try:
        async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
            time_config = await CoreProfileSessionTap.get_time_config(dvt)
            async with CoreProfileSessionTap(dvt, time_config) as tap:
                data = await tap.get_stackshot()
    except InvalidServiceError:
        pytest.skip("Skipping DVT-based test since the service isn't accessible")

    assert "Darwin Kernel" in data["osversion"]
    # Constant kernel task data.
    assert data["task_snapshots"][0]["task_snapshot"]["ts_pid"] == 0
    assert data["task_snapshots"][0]["task_snapshot"]["ts_p_comm"] == "kernel_task"
