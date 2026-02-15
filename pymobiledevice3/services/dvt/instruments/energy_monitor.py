from pymobiledevice3.services.remote_server import MessageAux


class EnergyMonitor:
    IDENTIFIER = "com.apple.xcode.debug-gauge-data-providers.Energy"

    def __init__(self, dvt, pid_list: list) -> None:
        self._dvt = dvt
        self._channel = None
        self._pid_list = pid_list

    async def _channel_ref(self):
        if self._channel is None:
            self._channel = await self._dvt.make_channel(self.IDENTIFIER)
        return self._channel

    async def __aenter__(self):
        channel = await self._channel_ref()
        # stop monitoring if already monitored
        await channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

        await channel.startSamplingForPIDs_(MessageAux().append_obj(self._pid_list))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        channel = await self._channel_ref()
        await channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

    def __aiter__(self):
        while True:
            yield self._sample_once()

    async def _sample_once(self):
        channel = await self._channel_ref()
        await channel.sampleAttributes_forPIDs_(MessageAux().append_obj({}).append_obj(self._pid_list))
        return await channel.receive_plist()
