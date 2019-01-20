#!/usr/bin/env python
# coding: utf-8
import logging
import config
import json
import argparse
from auth import get_claims

from jose import jwt, JWTError
from warrant import Cognito

env = 'dev'
config = config.get_config()[env]

LOG_FORMAT = ('%(levelname) -10s %(asctime)s %(funcName) '
              '-35s %(lineno) -5d: %(message)s')

LOGGER = logging.getLogger(__name__)


#get credentials for user
def authenticate_user(config, username, password):

    u = Cognito(config['aws']['cognitio']['userPoolId'],
                config['aws']['cognitio']['userPoolClientId'],
                username=username)
    u.authenticate(password=password)
    user = u.get_user(attr_map={"given_name":"first_name","family_name":"last_name"})

    print user.username, user.email_verified, u.access_token

    return u.access_token


class WarrantException(Exception):
    """Base class for all Warrant exceptions"""


class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""


class TokenVerificationException(WarrantException):
    """Raised when token verification fails."""

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("username", help="the user to make a token for.")
    parser.add_argument("password", help="the user password.")
    args = parser.parse_args()

    jwt_token = authenticate_user(config, args.username, args.password)
    event = {'authorizationToken': 'Bearer {0}'.format(jwt_token)}
    claims = get_claims(event, None)

    print json.dumps(claims)
