import logging
from typing import TYPE_CHECKING, Tuple
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from ._base import client_patterns
from synapse.http.site import SynapseRequest
from synapse.types import JsonMapping
from synapse.http.server import HttpServer
from synapse.api.errors import SynapseError
from synapse.http.client import SimpleHttpClient
from synapse.http import RequestTimedOutError
from synapse.api.errors import  Codes

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ThreepidRestServlet(RestServlet):
    PATTERNS = client_patterns("/user/threepid/bind")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.http_client = SimpleHttpClient(hs)
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonMapping]:
        """
        This route is only for appservice to add the threepids for it's users
        """
        requester = await self.auth.get_user_by_req(request, allow_guest=False)

        body = parse_json_object_from_request(request)

        if not requester.app_service:
            raise SynapseError(400, "Only appservices are allowed to use this route")

        added = await self.identity_handler.add_threepid(
            body["mxid"], body["org_id"], body["3pids"])

        if added:
            return 204, {}

        raise SynapseError(403, "Failed to add threepid(s)", Codes.FORBIDDEN)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ThreepidRestServlet(hs).register(http_server)