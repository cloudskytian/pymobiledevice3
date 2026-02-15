from pymobiledevice3.services.remote_server import MessageAux


class ApplicationListing:
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    def __init__(self, dvt):
        self._dvt = dvt
        self._channel = None

    async def _channel_ref(self):
        if self._channel is None:
            self._channel = await self._dvt.make_channel(self.IDENTIFIER)
        return self._channel

    async def applist(self) -> list:
        """
        Get the applications list from the device.
        :return: List of applications and their attributes.
        """
        channel = await self._channel_ref()
        await channel.installedApplicationsMatching_registerUpdateToken_(MessageAux().append_obj({}).append_obj(""))
        result = await channel.receive_plist()
        assert isinstance(result, list)
        return result
