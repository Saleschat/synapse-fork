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


if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UserLookupRestServlet(RestServlet):
    PATTERNS = client_patterns("/user/lookup")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.http_client = SimpleHttpClient(hs)
        self.identity_handler = hs.get_identity_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonMapping]:
        """Sends a request to the identity server with the search_term.
        This is a proxy route to hide the existence of identity server from
        the user

        Returns:
            dict of the form::

                {
                    "mappings": List[str]
                }
        """
        requester = await self.auth.get_user_by_req(request, allow_guest=False)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        if "search_term" not in body:
            raise SynapseError(400, "`search_term` is required field")

        search_term = body["search_term"]

        if search_term == "":
            raise SynapseError(400, "`search_term` cannot be empty")

        mxids = await self.identity_handler.user_lookup(user_id, search_term)

        return 200, {"mappings": mxids}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    UserLookupRestServlet(hs).register(http_server)
