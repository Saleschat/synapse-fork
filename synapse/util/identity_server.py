from synapse.util.caches.lrucache import LruCache
import logging
from typing import Optional, TYPE_CHECKING
from synapse.http.client import SimpleHttpClient
from synapse.util.stringutils import random_string
from synapse.http import RequestTimedOutError

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

class IdentityServer:
    """
    Manages identity server access token operations for a user
    """

    def __init__(self, hs: "HomeServer") -> None:
        self.cache: LruCache[str, str] = LruCache(cache_name= "identity_server_tokens", max_size=200)
        self.hs = hs
        self.http_client = SimpleHttpClient(hs)
        self.store = hs.get_datastores().main

    async def get_token_for_user(self, user_id: str) -> Optional[str]:
        if not isinstance(user_id, str):
            raise TypeError("user_id should be of type str")

        token = self.cache.get(user_id)

        if token is not None:
            return token
        
        # the token is not there so get the token from the identity server
        token = await self._get_token_from_server(user_id)

        if token is not None:
            self.cache.set(user_id, token)

        logger.error("Identity server didn't return any token for user %s", user_id)

        return token

    async def _get_token_from_server(self, user_id: str) -> Optional[str]:
        """
        Fetches the access token from the identity server and returns it
        """
        EXPIRES_MS = 3600 * 1000
        identity_server_host = self.hs.config.identity_server.identity_server_host
        access_token = random_string(24)

        if identity_server_host is None:
            logger.error("identity_server_host value not found")
            return None

        try:
            lookup_result = await self.http_client.post_json_get_json(
                "https://%s/_matrix/identity/v2/account/register" % (identity_server_host),
                {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "matrix_server_name": self.hs.config.server.server_name,
                    "expires_in": EXPIRES_MS // 1000,
                }
            )

        except RequestTimedOutError:
            logger.error("Request timed out: Failed to contact identity server to generate token for user %s", user_id)
            return None
        except Exception as e:
            logger.error("An error occured while contacting the identity server: %s", e)
            return None
        
        if "token" not in lookup_result:
            return lookup_result["token"]
        
        return None

