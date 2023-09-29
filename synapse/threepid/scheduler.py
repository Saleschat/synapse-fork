import logging
from typing import TYPE_CHECKING, List, Dict, Any
from synapse.handlers.identity import ThreePid
from synapse.metrics.background_process_metrics import run_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

default_loop_call_msec = 5


class ThreepidSyncScheduler:
    def __init__(self, hs: "HomeServer"):
        self.queue: List[Dict[str, Any]] = []
        self.backoff_counter = 1
        self.clock = hs.get_clock()
        self.identity_handler = hs.get_identity_handler()
        self.syncing = False

    def _try(self) -> None:
        run_as_background_process(
            "threepid sync", self._sync
        )

    def loop(self):
        """Don't call this function directly, please!!!"""
        delay = 2 ** self.backoff_counter if self.backoff_counter > 2 else default_loop_call_msec

        self.clock.call_later(delay, self._try)

    def enqueue_for_threepid_sync(self, mxid: str, threepids: List[ThreePid]):
        self.queue.append({"mxid": mxid, "threepids": threepids})

    async def _sync(self) -> None:
        """Don't call this function directly, please!!!"""
        if len(self.queue) == 0:
            self.backoff_counter = 1
            self.loop()
            return

        obj: Dict[str, Any] = {}
        logger.info("Threepid sync starting")
        unsuccessful_call = False
        while len(self.queue) > 0:
            obj = self.queue.pop()
            try:
                await self.identity_handler.add_threepid(obj["mxid"], obj["value"])

            except Exception as e:
                logger.error("%s", e)
                # TODO: handle errors please
                unsuccessful_call = True
                break

        # if the request was not successful, add the item back to the queue
        # and backoff
        if unsuccessful_call:
            self.queue.append(obj)
            self._backoff()
            return

        self.backoff_counter = 1
        self.loop()

    def _backoff(self) -> None:
        """Don't call this function directly"""
        if self.backoff_counter < 9:
            self.backoff_counter += 1

        self.loop()
