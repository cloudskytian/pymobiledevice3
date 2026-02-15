from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService


class Screenshot:
    IDENTIFIER = "com.apple.instruments.server.services.screenshot"

    def __init__(self, dvt: DvtSecureSocketProxyService):
        self._dvt = dvt
        self._channel = None

    async def _channel_ref(self):
        if self._channel is None:
            self._channel = await self._dvt.make_channel(self.IDENTIFIER)
        return self._channel

    async def get_screenshot(self) -> bytes:
        """get device screenshot"""
        channel = await self._channel_ref()
        await channel.takeScreenshot(expects_reply=True)
        return await channel.receive_plist()
