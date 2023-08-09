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
from typing import TYPE_CHECKING

from authlib.jose import JsonWebToken, JWTClaims
from authlib.jose.errors import BadSignatureError, InvalidClaimError, JoseError

from synapse.api.errors import Codes, LoginError, JWTDecodeFailed
from synapse.types import JsonDict, UserID

from authlib.oidc.core import UserInfo
from synapse.handlers.sso import UserAttributes

if TYPE_CHECKING:
    from synapse.server import HomeServer


class JwtHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs

        self.jwt_secret = hs.config.jwt.jwt_secret
        self.jwt_subject_claim = hs.config.jwt.jwt_subject_claim
        self.jwt_algorithm = hs.config.jwt.jwt_algorithm
        self.jwt_issuer = hs.config.jwt.jwt_issuer
        self.jwt_audiences = hs.config.jwt.jwt_audiences
        self.jwt_user_mapping_provider = hs.config.jwt.jwt_user_mapping_provider

    def _get_claims_from_token(self, token) -> JWTClaims:
        jwt = JsonWebToken([self.jwt_algorithm])

        claim_options = {}

        if self.jwt_issuer is not None:
            claim_options["iss"] = {"value": self.jwt_issuer, "essential": True}
        if self.jwt_audiences is not None:
            claim_options["aud"] = {"values": self.jwt_audiences, "essential": True}

        claims = jwt.decode(
            token,
            key=self.jwt_secret,
            claims_cls=JWTClaims,
            claims_options=claim_options,
        )

        return claims

    def validate_login(self, login_submission: JsonDict) -> str:
        """
        Authenticates the user for the /login API

        Args:
            login_submission: the whole of the login submission
                (including 'type' and other relevant fields)

        Returns:
            The user ID that is logging in.

        Raises:
            LoginError if there was an authentication problem.
        """
        token = login_submission.get("token", None)
        if token is None:
            raise LoginError(
                403, "Token field for JWT is missing", errcode=Codes.FORBIDDEN
            )

        jwt = JsonWebToken([self.jwt_algorithm])
        claim_options = {}
        if self.jwt_issuer is not None:
            claim_options["iss"] = {"value": self.jwt_issuer, "essential": True}
        if self.jwt_audiences is not None:
            claim_options["aud"] = {"values": self.jwt_audiences, "essential": True}

        try:
            claims = self._get_claims_from_token(token)
        except BadSignatureError:
            # We handle this case separately to provide a better error message
            raise LoginError(
                403,
                "JWT decode failed: Signature verification failed",
                errcode=Codes.FORBIDDEN,
            )
        except JoseError as e:
            # A JWT error occurred, return some info back to the client.
            raise LoginError(
                403,
                "JWT validation failed: %s" % (str(e),),
                errcode=Codes.FORBIDDEN,
            )

        try:
            claims.validate(leeway=120)  # allows 2 min of clock skew

            # Enforce the old behavior which is rolled out in productive
            # servers: if the JWT contains an 'aud' claim but none is
            # configured, the login attempt will fail
            if claims.get("aud") is not None:
                if self.jwt_audiences is None or len(self.jwt_audiences) == 0:
                    raise InvalidClaimError("aud")
        except JoseError as e:
            raise LoginError(
                403,
                "JWT validation failed: %s" % (str(e),),
                errcode=Codes.FORBIDDEN,
            )

        user = claims.get(self.jwt_subject_claim, None)
        if user is None:
            raise LoginError(403, "Invalid JWT", errcode=Codes.FORBIDDEN)

        return UserID(user, self.hs.hostname).to_string()

    async def get_user_attributes_from_token(
        self, login_submission: JsonDict
    ) -> UserAttributes:
        """
        Parses the user attributes that are set in the claims of a jwt token

        Args:
            login_submission: the whole of the login submission
                (including 'type' and other relevant fields)

        Returns:
            The user attributes set into token claims.

        Raises:
            JWTDecodeFailed
        """

        # return empty user attributes jwt_user_mapping_provider is None
        # This makes sure that no exception is raised
        if self.jwt_user_mapping_provider is None:
            return None

        token = login_submission.get("token")

        try:
            claims = self._get_claims_from_token(token)

        except JoseError as e:
            # A JWT error occurred, return some info back to the client.
            raise JWTDecodeFailed(
                "JWT decode failed: %s" % (str(e),),
            )

        userinfo = UserInfo(claims)
        attributes = await self.jwt_user_mapping_provider.map_user_attributes(
            userinfo, token, 0
        )

        return UserAttributes(**attributes)
