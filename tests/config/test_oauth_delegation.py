# Copyright 2023 Matrix.org Foundation C.I.C.
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

from typing import Any, Dict
from unittest.mock import Mock

from synapse.config import ConfigError
from synapse.module_api import ModuleApi
from synapse.types import JsonDict

from tests.server import get_clock
from tests.unittest import HomeserverTestCase, override_config, skip_unless

try:
    import authlib  # noqa: F401

    HAS_AUTHLIB = True
except ImportError:
    HAS_AUTHLIB = False


# These are a few constants that are used as config parameters in the tests.
SERVER_NAME = "test"
ISSUER = "https://issuer/"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
BASE_URL = "https://synapse/"


class CustomAuthModule:
    """A module which registers a password auth provider."""

    @staticmethod
    def parse_config(config: JsonDict) -> None:
        pass

    def __init__(self, config: None, api: ModuleApi):
        api.register_password_auth_provider_callbacks(
            auth_checkers={("m.login.password", ("password",)): Mock()},
        )


def _dict_merge(merge_dict: dict, into_dict: dict) -> None:
    """Do a deep merge of two dicts

    Recursively merges `merge_dict` into `into_dict`:
      * For keys where both `merge_dict` and `into_dict` have a dict value, the values
        are recursively merged
      * For all other keys, the values in `into_dict` (if any) are overwritten with
        the value from `merge_dict`.

    Args:
        merge_dict: dict to merge
        into_dict: target dict to be modified
    """
    for k, v in merge_dict.items():
        if k not in into_dict:
            into_dict[k] = v
            continue

        current_val = into_dict[k]

        if isinstance(v, dict) and isinstance(current_val, dict):
            _dict_merge(v, current_val)
            continue

        # otherwise we just overwrite
        into_dict[k] = v


@skip_unless(HAS_AUTHLIB, "requires authlib")
class MSC3861OAuthDelegation(HomeserverTestCase):
    """Test that the Homeserver fails to initialize if the config is invalid."""

    def setUp(self) -> None:
        self.reactor, self.clock = get_clock()
        self._hs_args = {"clock": self.clock, "reactor": self.reactor}

    def default_config(self) -> Dict[str, Any]:
        default_extra_config = {
            "public_baseurl": BASE_URL,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": ISSUER,
                    "client_id": CLIENT_ID,
                    "client_auth_method": "client_secret_post",
                    "client_secret": CLIENT_SECRET,
                }
            },
        }
        _dict_merge(
            {} if self._extra_config is None else self._extra_config,
            default_extra_config,
        )
        self._extra_config = default_extra_config
        return super().default_config()

    @override_config(
        {
            "enable_registration": False,
        }
    )
    def test_client_secret_post_works(self) -> None:
        self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3861": {
                    "client_auth_method": "invalid",
                }
            },
        }
    )
    def test_invalid_client_auth_method(self) -> None:
        with self.assertRaises(ValueError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3861": {
                    "client_auth_method": "private_key_jwt",
                }
            },
        }
    )
    def test_invalid_private_key_jwt(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3861": {
                    "client_auth_method": "private_key_jwt",
                    "jwk": {
                        "p": "-frVdP_tZ-J_nIR6HNMDq1N7aunwm51nAqNnhqIyuA8ikx7LlQED1tt2LD3YEvYyW8nxE2V95HlCRZXQPMiRJBFOsbmYkzl2t-MpavTaObB_fct_JqcRtdXddg4-_ihdjRDwUOreq_dpWh6MIKsC3UyekfkHmeEJg5YpOTL15j8",
                        "kty": "RSA",
                        "q": "oFw-Enr_YozQB1ab-kawn4jY3yHi8B1nSmYT0s8oTCflrmps5BFJfCkHL5ij3iY15z0o2m0N-jjB1oSJ98O4RayEEYNQlHnTNTl0kRIWzpoqblHUIxVcahIpP_xTovBJzwi8XXoLGqHOOMA-r40LSyVgP2Ut8D9qBwV6_UfT0LU",
                        "d": "WFkDPYo4b4LIS64D_QtQfGGuAObPvc3HFfp9VZXyq3SJR58XZRHE0jqtlEMNHhOTgbMYS3w8nxPQ_qVzY-5hs4fIanwvB64mAoOGl0qMHO65DTD_WsGFwzYClJPBVniavkLE2Hmpu8IGe6lGliN8vREC6_4t69liY-XcN_ECboVtC2behKkLOEASOIMuS7YcKAhTJFJwkl1dqDlliEn5A4u4xy7nuWQz3juB1OFdKlwGA5dfhDNglhoLIwNnkLsUPPFO-WB5ZNEW35xxHOToxj4bShvDuanVA6mJPtTKjz0XibjB36bj_nF_j7EtbE2PdGJ2KevAVgElR4lqS4ISgQ",
                        "e": "AQAB",
                        "kid": "test",
                        "qi": "cPfNk8l8W5exVNNea4d7QZZ8Qr8LgHghypYAxz8PQh1fNa8Ya1SNUDVzC2iHHhszxxA0vB9C7jGze8dBrvnzWYF1XvQcqNIVVgHhD57R1Nm3dj2NoHIKe0Cu4bCUtP8xnZQUN4KX7y4IIcgRcBWG1hT6DEYZ4BxqicnBXXNXAUI",
                        "dp": "dKlMHvslV1sMBQaKWpNb3gPq0B13TZhqr3-E2_8sPlvJ3fD8P4CmwwnOn50JDuhY3h9jY5L06sBwXjspYISVv8hX-ndMLkEeF3lrJeA5S70D8rgakfZcPIkffm3tlf1Ok3v5OzoxSv3-67Df4osMniyYwDUBCB5Oq1tTx77xpU8",
                        "dq": "S4ooU1xNYYcjl9FcuJEEMqKsRrAXzzSKq6laPTwIp5dDwt2vXeAm1a4eDHXC-6rUSZGt5PbqVqzV4s-cjnJMI8YYkIdjNg4NSE1Ac_YpeDl3M3Colb5CQlU7yUB7xY2bt0NOOFp9UJZYJrOo09mFMGjy5eorsbitoZEbVqS3SuE",
                        "n": "nJbYKqFwnURKimaviyDFrNLD3gaKR1JW343Qem25VeZxoMq1665RHVoO8n1oBm4ClZdjIiZiVdpyqzD5-Ow12YQgQEf1ZHP3CCcOQQhU57Rh5XvScTe5IxYVkEW32IW2mp_CJ6WfjYpfeL4azarVk8H3Vr59d1rSrKTVVinVdZer9YLQyC_rWAQNtHafPBMrf6RYiNGV9EiYn72wFIXlLlBYQ9Fx7bfe1PaL6qrQSsZP3_rSpuvVdLh1lqGeCLR0pyclA9uo5m2tMyCXuuGQLbA_QJm5xEc7zd-WFdux2eXF045oxnSZ_kgQt-pdN7AxGWOVvwoTf9am6mSkEdv6iw",
                    },
                }
            },
        }
    )
    def test_private_key_jwt_works(self) -> None:
        self.setup_test_homeserver()

    def test_registration_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "password_config": {
                "enabled": True,
            },
        }
    )
    def test_password_config_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "oidc_providers": [
                {
                    "idp_id": "microsoft",
                    "idp_name": "Microsoft",
                    "issuer": "https://login.microsoftonline.com/<tenant id>/v2.0",
                    "client_id": "<client id>",
                    "client_secret": "<client secret>",
                    "scopes": ["openid", "profile"],
                    "authorization_endpoint": "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/authorize",
                    "token_endpoint": "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token",
                    "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
                }
            ],
        }
    )
    def test_oidc_sso_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "cas_config": {
                "enabled": True,
                "server_url": "https://cas-server.com",
                "displayname_attribute": "name",
                "required_attributes": {"userGroup": "staff", "department": "None"},
            },
        }
    )
    def test_cas_sso_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "modules": [
                {
                    "module": f"{__name__}.{CustomAuthModule.__qualname__}",
                    "config": {},
                }
            ],
        }
    )
    def test_auth_providers_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "jwt_config": {
                "enabled": True,
                "secret": "my-secret-token",
                "algorithm": "HS256",
            },
        }
    )
    def test_jwt_auth_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3882_enabled": True,
            },
        }
    )
    def test_msc3882_auth_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "recaptcha_public_key": "test",
            "recaptcha_private_key": "test",
            "enable_registration_captcha": True,
        }
    )
    def test_captcha_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "refresh_token_lifetime": "24h",
            "refreshable_access_token_lifetime": "10m",
            "nonrefreshable_access_token_lifetime": "24h",
        }
    )
    def test_refreshable_tokens_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "session_lifetime": "24h",
        }
    )
    def test_session_lifetime_cannot_be_set(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()