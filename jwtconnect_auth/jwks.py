import datetime
import logging

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_bundle import KeyBundle
from django.conf import settings
from django.utils import timezone
from django.utils.module_loading import import_string
from oidcmsg.message import Message

from . exceptions import InvalidJWT
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
        keyjar.import_jwks(jwks, issuer=getattr(settings, 
                                                'JWTAUTH_ISSUER', ""))
        return keyjar
    
    @classmethod
    def decode_jwt(cls, jwt, verify=True, format='dict'):
        keyjar = cls.keyjar()
        
        try:
            jwt = Message().from_jwt(jwt, keyjar=keyjar)
            jwt.verify()
        except Exception as e:
            logger.error(e)
            raise InvalidJWT('Not a valid JWT: signature failed on save.')
        if format:
            return getattr(jwt, 'to_{}'.format(format))()
        else:
            return jwt

class JWTConnectAuthTokenBuilder(object):
    
    @staticmethod
    def build(user=None, **kwargs):
        """
        user: a django user
        """
        kwargs['iat'] = int(timezone.localtime().timestamp())
        if getattr(settings, 'JWTAUTH_ISSUER', None):
            kwargs['iss'] = settings.JWTAUTH_ISSUER

        if user:
            kwargs['sub'] = get_hash(user.username)
            userinfo = {v:getattr(user, k)
                        for k,v in JWTAUTH_CLAIMS_MAP.items()}
                        # if getattr(user, k)}
        else:
            userinfo = {}
        
        expires_in = kwargs.get('expires_in', JWTAUTH_ACCESS_TOKEN_LIFETIME)
        
        # ACCESS TOKEN
        access_token = kwargs.copy()
        access_token['jti'] = get_random_hash()
        access_token['ttype'] = 'T'
        atoken_lifetime = JWTAUTH_ACCESS_TOKEN_LIFETIME
        access_token['exp'] = int((timezone.localtime() + \
                                   datetime.timedelta(seconds=atoken_lifetime))\
                                  .timestamp())
        access_token.update(userinfo)

        # REFRESH TOKEN
        rtoken = kwargs.copy()
        rtoken['ttype'] = 'R'
        rtoken['jti'] = get_random_hash()
        rtoken_lifetime = JWTAUTH_REFRESH_TOKEN_LIFETIME
        rtoken['exp'] = int((timezone.localtime() + \
                             datetime.timedelta(seconds=rtoken_lifetime))\
                            .timestamp())
        return dict(access_token=access_token, 
                    refresh_token=rtoken,
                    expires_in = expires_in)

    @staticmethod
    def create(data, alg=None, lifetime=None , **kwargs):
        """
        Only signed JWT from here
        """
        alg = alg or JWTAUTH_ALGORITHM
        keys = import_string(JWTAUTH_KEYJAR_HANDLER).keys()

        access_token, rtoken = data['access_token'], data['refresh_token']
        return {'access_token': Message(**access_token).to_jwt(keys, alg),
                'refresh_token': Message(**rtoken).to_jwt(keys, alg),
                'token_type': 'bearer',
                'expires_in': lifetime or data.get('expires_in', 
                                                   JWTAUTH_ACCESS_TOKEN_LIFETIME)}
                
