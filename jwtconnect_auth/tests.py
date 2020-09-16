import logging
import json

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from . jwks import JWTConnectAuthTokenBuilder
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

    
    def test_create_user_jwt(self):
        user = get_user_model().objects.create(**_user_dict)
        jwk_store = JWTConnectAuthToken.create(user=user)
        return jwk_store

        
    def test_token_instrospection(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        rtoken = jwk_store.refresh_token
        headers = {'Authorization': 'Bearer f{atoken}'}
        url = reverse('jwtconnect_auth:token_introspection')
        req = Client().post(url, headers=headers, 
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': atoken}).json()
        assert len(req.keys()) > 3

        req = Client().post(url, headers=headers, 
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': rtoken}).json()
        assert len(req.keys()) > 3


    def test_token_refresh(self):
        jwk_store = self.test_create_user_jwt()
        atoken = jwk_store.access_token
        headers = {'Authorization': 'Bearer f{atoken}'}
        url = reverse('jwtconnect_auth:token_refresh')
        req = Client().post(url, headers=headers, 
                            HTTP_ACCEPT='application/json',
                            content_type='application/json',
                            data={'token': jwk_store.refresh_token}).json()
        assert len(req.keys()) == 2 and 'access_token' in req
        
