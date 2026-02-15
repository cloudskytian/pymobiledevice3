from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.remote_server import MessageAux


class LocationSimulation(LocationSimulationBase):
    IDENTIFIER = "com.apple.instruments.server.services.LocationSimulation"

    def __init__(self, dvt):
        super().__init__()
        self._dvt = dvt
        self._channel = None

    async def _channel_ref(self):
        if self._channel is None:
            self._channel = await self._dvt.make_channel(self.IDENTIFIER)
        return self._channel

    async def set(self, latitude: float, longitude: float) -> None:
        channel = await self._channel_ref()
        await channel.simulateLocationWithLatitude_longitude_(MessageAux().append_obj(latitude).append_obj(longitude))
        await channel.receive_plist()

    async def clear(self) -> None:
        channel = await self._channel_ref()
        await channel.stopLocationSimulation()
