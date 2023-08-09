# Copyright 2015 Niklas Riekenbrauck
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any

from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements

from ._base import Config
from synapse.util.module_loader import load_module


DEFAULT_USER_MAPPING_PROVIDER = "synapse.handlers.oidc.JinjaOidcMappingProvider"


class JWTConfig(Config):
    section = "jwt"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        jwt_config = config.get("jwt_config", None)
        if jwt_config:
            self.jwt_enabled = jwt_config.get("enabled", False)
            self.jwt_secret = jwt_config["secret"]
            self.jwt_algorithm = jwt_config["algorithm"]

            self.jwt_subject_claim = jwt_config.get("subject_claim", "sub")

            # The issuer and audiences are optional, if provided, it is asserted
            # that the claims exist on the JWT.
            self.jwt_issuer = jwt_config.get("issuer")
            self.jwt_audiences = jwt_config.get("audiences")

            user_mapping_provider = jwt_config.get("user_mapping_provider", {})
            if user_mapping_provider is not None:
                config = user_mapping_provider.get("config")
                if config is not None:
                    user_mapping_provider.setdefault(
                        "module", DEFAULT_USER_MAPPING_PROVIDER
                    )

                    (
                        user_mapping_provider_class,
                        user_mapping_provider_config,
                    ) = load_module(
                        user_mapping_provider,
                        (
                            "jwt_config",
                            "user_mapping_provider",
                        ),
                    )

                    self.jwt_user_mapping_provider = user_mapping_provider_class(
                        user_mapping_provider_config
                    )
                else:
                    self.jwt_user_mapping_provider = None

            check_requirements("jwt")
        else:
            self.jwt_enabled = False
            self.jwt_secret = None
            self.jwt_algorithm = None
            self.jwt_subject_claim = None
            self.jwt_issuer = None
            self.jwt_audiences = None
            self.jwt_user_mapping_provider = None
