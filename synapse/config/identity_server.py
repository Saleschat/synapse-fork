from typing import Any

from ._base import Config
from synapse.types import JsonDict

class IdentityServerConfig(Config):
    section = "identity_server"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        #read the url of the identity server
        self.identity_server_host = config.get("identity_server_host")