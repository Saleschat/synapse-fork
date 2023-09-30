import logging
from typing import TYPE_CHECKING, Tuple, Dict, Any
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

        self.validate_key(body, "mxid")
        self.validate_key(body, "org_id")

        if "3pids" not in body or not isinstance(body["3pids"], list) or len(body["3pids"]) == 0:
            raise SynapseError(400, "3pids should be a non-empty list")

        if not requester.app_service:
            raise SynapseError(403,
                               "Only appservices are allowed to use this route",
                               Codes.FORBIDDEN)

        threepids = body["3pids"]
        threepids.append({"key": "org_id", "value": body["org_id"]})
        mxid = body["mxid"]

        self.hs.get_threepid_sync_scheduler().enqueue_for_threepid_sync(mxid, threepids)

        return 202, {}

    @staticmethod
    def validate_key(body: Dict[str, Any], key: str):
        if key not in body or not isinstance(body[key], str):
            raise SynapseError(400,
                               "%s is required in the body" % (key,),
                               Codes.MISSING_PARAM)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ThreepidRestServlet(hs).register(http_server)