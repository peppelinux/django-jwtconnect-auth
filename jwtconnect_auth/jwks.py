import datetime
import logging

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_bundle import KeyBundle
from django.conf import settings
from django.utils.module_loading import import_string
from oidcmsg.message import Message

from . settings import *
from . utils import get_random_hash, get_hash


logger = logging.getLogger('__name__')


JWTAUTH_ALGORITHM = getattr(settings, 'JWTAUTH_ALGORITHM',
                            DEFAULT_JWTAUTH_ALGORITHM)
JWTAUTH_CLAIMS_MAP = getattr(settings, 'JWTAUTH_CLAIMS_MAP',
                             DEFAULT_JWTAUTH_CLAIMS_MAP)
JWTAUTH_ACCESS_TOKEN_LIFETIME = getattr(settings, 'JWTAUTH_ACCESS_TOKEN_LIFETIME',
                                        DEFAULT_JWTAUTH_ACCESS_TOKEN_LIFETIME)
JWTAUTH_REFRESH_TOKEN_LIFETIME = getattr(settings, 'JWTAUTH_REFRESH_TOKEN_LIFETIME',
                                         DEFAULT_JWTAUTH_REFRESH_TOKEN_LIFETIME)
JWTAUTH_KEYJAR_HANDLER = getattr(settings,
                                 'JWTAUTH_KEYJAR_HANDLER',
                                 DEFAULT_JWTAUTH_KEYJAR_HANDLER)
JWTAUTH_CLAIMS_MAP = getattr(settings, 'JWTAUTH_CLAIMS_MAP',
                             DEFAULT_JWTAUTH_CLAIMS_MAP)


class JWTConnectAuthKeyHandler(object):
    @staticmethod
    def keys() -> list:
        """
        gives you the keys in a quite usable way
        """
        # Asymmetric
        if settings.JWTAUTH_KEY and settings.JWTAUTH_CERT:
            public = settings.JWTAUTH_CERT
            private = settings.JWTAUTH_KEY
            keys = [RSAKey(priv_key=private)]
        # Symmetric
        else:
            keys = [SYMKey(key=settings.JWTAUTH_KEY)]
        return keys

    @classmethod
    def keyjar(cls):
        """
        Key jar, the place where you store all the keys
        """
        keyjar = KeyJar()
        keys = cls.keys()
        jwks = {'keys': [key.serialize(private=True) for key in keys]}
        keyjar.import_jwks(jwks, issuer=getattr(settings, 'JWTAUTH_ISSUER', ""))
        return keyjar


class JWTConnectAuthTokenBuilder(object):
    @staticmethod
    def build(user=None, **kwargs):
        """
        user: a django user
        """
        kwargs['iat'] = int(datetime.datetime.now().timestamp())
        if getattr(settings, 'JWTAUTH_ISSUER', None):
            kwargs['iss'] = settings.JWTAUTH_ISSUER

        if user:
            kwargs['sub'] = get_hash(user.username)
            userinfo = {v:getattr(user, k)
                        for k,v in JWTAUTH_CLAIMS_MAP.items()}
                        # if getattr(user, k)}
        else:
            userinfo = {}

        # ACCESS TOKEN
        access_token = kwargs.copy()
        access_token['jti'] = get_random_hash()
        access_token['ttype'] = 'T'
        atoken_lifetime = JWTAUTH_ACCESS_TOKEN_LIFETIME
        access_token['exp'] = int((datetime.datetime.now() + \
                                   datetime.timedelta(seconds=atoken_lifetime))\
                                  .timestamp())
        access_token.update(userinfo)

        # REFRESH TOKEN
        rtoken = kwargs.copy()
        rtoken['ttype'] = 'R'
        rtoken['jti'] = get_random_hash()
        rtoken_lifetime = JWTAUTH_REFRESH_TOKEN_LIFETIME
        rtoken['exp'] = int((datetime.datetime.now() + \
                            datetime.timedelta(seconds=rtoken_lifetime))\
                            .timestamp())
        return dict(access=access_token, refresh=rtoken)

    @classmethod
    def create(cls, data, alg=None, **kwargs):
        alg = alg or getattr(settings,
                             'JWTAUTH_ALGORITHM', DEFAULT_JWTAUTH_ALGORITHM)
        keys = import_string(JWTAUTH_KEYJAR_HANDLER).keys()

        access_token, rtoken = data.values()
        return {'access': Message(**access_token).to_jwt(keys, JWTAUTH_ALGORITHM),
                'refresh': Message(**rtoken).to_jwt(keys, JWTAUTH_ALGORITHM)}
