#!/usr/bin/env python
# coding: utf-8
import logging
import config
import json

from jose import jwt, JWTError
from warrant import Cognito

env = 'dev'
config = config.get_config()[env]

LOG_FORMAT = ('%(levelname) -10s %(asctime)s %(funcName) '
              '-35s %(lineno) -5d: %(message)s')

LOGGER = logging.getLogger(__name__)

COGNITO_JWKS={"keys":[{"alg":"RS256","e":"AQAB","kid":"BuYbWvWYmEOknHJHLO9xoJ2Bz1W3Pc6OjjOhUS7rLSg=","kty":"RSA","n":"oT8qw_nqF9w7vaH23kpRXtVGCIFdBSpqYSugndOKO5vhoFrY5ycGayO5iGNmnF91UtYAbpvxJdQ2Sn5-IkkmciSPM2j0cTitQ5XkKx3atU5N8-XExJ1RDFZsyLQB1H2p_9XdCuvAVOVlwxZOJzXUsuQt1rIdHdnb7NrWC5iyDuRgBHiqDyt_eN8UiTdlODRQDn14kbvjI9wLd63L2Y0vPXChfaEYpbfsgeIyYBy0cTSeJa6qITbeVx1B3cBfivR9zMGvca6zOAPPb1ejq5d8orHHjKWyE0qbDRqvpXSrA84D4UlBB4pJxkxWGnQwj1oCpiIveHmhtkQFqJWj-PqSVQ","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"oBwIcJB/v387OrZ+fF1UDN3N6SF3vPBH9yiuU33mwJw=","kty":"RSA","n":"rBHYlqaPZYrfEyzu3ABnOV2CPKB7dzwL7jxNu0Yt0UWNsO2JFiudZ4MiogMj7kxf8LA7KTvWz0jPJ85pkQ02VOkaIR2pYxuXKez132SRUSVFPCWXD7Q4FoDvclLWaJgFjsQSD87Jv2ttojHhD_EoA5HlRS6K4b8LUg2krKTFYNqHAKBFZoM6zbC33U-Ar4AseQTfzG0Aej_HX6j0Ul30GMf13wKPwyn1gD3iGH1eiNd69X6_yEMF5AJ7bJ6nPX3b4WIplynXF-BKEME9SkvihaCnNwktVkstdx5xWQc21JxEfHU0wrh9jWcvLT0ff6thDMgCWMbi6vwQNIy9dNRh4Q","use":"sig"}]}

#get credentials for user
def authenticate_user(config, username, password):

    u = Cognito(config['aws']['cognitio']['userPoolId'],
                config['aws']['cognitio']['userPoolClientId'],
                username=username)
    u.authenticate(password=password)
    user = u.get_user(attr_map={"given_name":"first_name","family_name":"last_name"})

    print user.username, user.email_verified, u.access_token

    return u.access_token


def get_key(kid, COGNITO_JWKS):
    keys = COGNITO_JWKS.get('keys')
    key = list(filter(lambda x:x.get('kid') == kid,keys))
    return key[0]

def verify_token(token,id_name,token_use):
    kid = jwt.get_unverified_header(token).get('kid')
    unverified_claims = jwt.get_unverified_claims(token)

    token_use_verified = unverified_claims.get('token_use') == token_use
    if not token_use_verified:
        raise TokenVerificationException('Your {} token use could not be verified.')
    hmac_key = get_key(kid, COGNITO_JWKS)
    try:
        verified = jwt.decode(token,hmac_key,algorithms=['RS256'],
               audience=unverified_claims.get('aud'),
               issuer=unverified_claims.get('iss'))
    except JWTError:
        raise TokenVerificationException('Your {} token could not be verified.')

    return verified


#make jwt token

#get public key
#https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PUkU7rkEP/.well-known/jwks.json

#verify token

def main():
    jwt_token = authenticate_user(config, "claytantor@gmail.com", 'Tangy45Batz!')
    verified = verify_token(jwt_token,'access_token','access')
    print json.dumps(verified)


class WarrantException(Exception):
    """Base class for all Warrant exceptions"""


class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""


class TokenVerificationException(WarrantException):
    """Raised when token verification fails."""

if __name__ == '__main__':
    main()
