import datetime
import logging
from abc import abstractmethod
from typing import Any, Optional

from pymobiledevice3.exceptions import StartServiceError
from pymobiledevice3.service_connection import ServiceConnection


class LockdownServiceProvider:
    def __init__(self):
        self.udid: Optional[str] = None
        self.product_type: Optional[str] = None

    @property
    @abstractmethod
    def product_version(self) -> str:
        pass

    @property
    @abstractmethod
    def product_build_version(self) -> str:
        pass

    @property
    @abstractmethod
    def ecid(self) -> int:
        pass

    @abstractmethod
    async def get_developer_mode_status(self) -> bool:
        pass

    @abstractmethod
    async def get_date(self) -> datetime.datetime:
        pass

    @abstractmethod
    async def set_language(self, language: str) -> None:
        pass

    @abstractmethod
    async def get_language(self) -> str:
        pass

    @abstractmethod
    async def set_locale(self, locale: str) -> None:
        pass

    @abstractmethod
    async def get_locale(self) -> str:
        pass

    @abstractmethod
    async def set_assistive_touch(self, value: bool) -> None:
        pass

    @abstractmethod
    async def get_assistive_touch(self) -> bool:
        pass

    @abstractmethod
    async def set_voice_over(self, value: bool) -> None:
        pass

    @abstractmethod
    async def get_voice_over(self) -> bool:
        pass

    @abstractmethod
    async def set_invert_display(self, value: bool) -> None:
        pass

    @abstractmethod
    async def get_invert_display(self) -> bool:
        pass

    @abstractmethod
    async def set_enable_wifi_connections(self, value: bool) -> None:
        pass

    @abstractmethod
    async def get_enable_wifi_connections(self) -> bool:
        pass

    @abstractmethod
    async def set_timezone(self, timezone: str) -> None:
        pass

    @abstractmethod
    async def set_uses24h_clock(self, value: bool) -> None:
        pass

    @abstractmethod
    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        pass

    @abstractmethod
    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        pass

    @abstractmethod
    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        pass

    @abstractmethod
    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        pass

    async def start_lockdown_developer_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        try:
            return await self.start_lockdown_service(name, include_escrow_bag=include_escrow_bag)
        except StartServiceError:
            logging.getLogger(self.__module__).exception(
                "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
                "You can do so using: pymobiledevice3 mounter mount"
            )
            raise
