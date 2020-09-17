import logging
import json

from cryptojwt.jwk.x509 import import_public_key_from_cert_file
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from . jwks import *
from . models import JWTConnectAuthToken


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_user_dict = dict(username='ciro', email='thatmail@ingoalla.org')


class JWTTests(TestCase):
    
    def test_create_signed_jwt(self):
        user = get_user_model().objects.create(**_user_dict)
        data = JWTConnectAuthTokenBuilder.build(user=user)
        logger.warn(json.dumps(data, indent=2))
        assert data['access_token']['email'] == user.email

        jwts = JWTConnectAuthTokenBuilder.create(data)
        logger.info(json.dumps(jwts, indent=2))
        assert 'access_token' in jwts.keys()
        assert 'refresh_token' in jwts.keys()
        
        atoken = JWTConnectAuthKeyHandler.decode_jwt(jwts['access_token'])
        assert isinstance(atoken, dict)


    def test_create_signed_jwt_symmetric(self):
        settings.JWTAUTH_ALGORITHM = 'HS256'
        settings.JWTAUTH_KEY = b'a897dya9s78dyasdya9sdya9s7dya9sd7y'
        settings.JWTAUTH_CERT = None
        
        user = get_user_model().objects.create(**_user_dict)
        data = JWTConnectAuthTokenBuilder.build(user=user)
        logger.warn(json.dumps(data, indent=2))
        assert data['access_token']['email'] == user.email
        
        jwts = JWTConnectAuthTokenBuilder.create(data, 
                                                 alg=settings.JWTAUTH_ALGORITHM)
        logger.info(json.dumps(jwts, indent=2))
        assert 'access_token' in jwts.keys()
        assert 'refresh_token' in jwts.keys()
        
        atoken = JWTConnectAuthKeyHandler.decode_jwt(jwts['access_token'])
        assert isinstance(atoken, dict)
        
        settings.JWTAUTH_ALGORITHM = 'RS256'
        settings.JWTAUTH_KEY = import_private_rsa_key_from_file('certs/private.key')
        settings.JWTAUTH_CERT = import_public_key_from_cert_file('certs/public.cert')
    

    def test_create_user_jwt(self):
        user = get_user_model().objects.create(**_user_dict)
        jwk_store = JWTConnectAuthToken.create(user=user)
        # jwk_store.aud = ['ciao', 'hola']
        return jwk_store

        
    def test_token_instrospection(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        rtoken = jwk_store.refresh_token
        url = reverse('jwtconnect_auth:token_introspection')
        req = Client().post(url,
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': atoken},
                            HTTP_AUTHORIZATION='Bearer {}'.format(atoken)
                            ).json()
        assert len(req.keys()) > 3

        req = Client().post(url,
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': rtoken},
                            HTTP_AUTHORIZATION='Bearer {}'.format(atoken)
                            ).json()
        assert len(req.keys()) > 3

    
    def test_token_introspection_noauth(self):
        url = reverse('jwtconnect_auth:token_introspection')
        req = Client().post(url,
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'jti': 'many things'})
        assert req.status_code == 403


    def test_token_refresh(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        url = reverse('jwtconnect_auth:token_refresh')
        req = Client().post(url, HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': jwk_store.refresh_token},
                            ).json()
        assert len(req.keys()) == 2 and 'access_token' in req
        
        settings.JWTAUTH_MULTIPLE_TOKENS = False
        JWTConnectAuthToken.create(user=jwk_store.user)
        JWTConnectAuthToken.create(user=jwk_store.user)
        req = Client().post(url,
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': jwk_store.refresh_token}).json()
        assert JWTConnectAuthToken.objects.filter(user=jwk_store.user).count() == 1
        

    def test_inexistent_token_refresh(self):
        url = reverse('jwtconnect_auth:token_refresh')
        req = Client().post(url, HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': 'that_thing'})
        assert req.status_code == 401


    def test_invalid_token_instrospection(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        rtoken = jwk_store.refresh_token
        url = reverse('jwtconnect_auth:token_introspection')
        req = Client().post(url,
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': 'INVALID'},
                            HTTP_AUTHORIZATION='Bearer {}'.format(atoken)
                            )
        assert req.status_code == 401


    def test_invalidtoken_refresh(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        url = reverse('jwtconnect_auth:token_refresh')
        req = Client().post(url, HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'INVALID': jwk_store.refresh_token},
                            )
        assert req.status_code == 400
