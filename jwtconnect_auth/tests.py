import logging
import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from jwtconnect_auth.jwks import JWTConnectAuthTokenBuilder


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class JWTTests(TestCase):
    def test_create_signed_jwt(self):
        user = get_user_model().objects.create(**dict(username='ciro',
                                                      email='thatmail@ingoalla.org'))
        data = JWTConnectAuthTokenBuilder.build(user=user)
        logger.warn(json.dumps(data, indent=2))
        assert data['access']['email'] == user.email

        jwts = JWTConnectAuthTokenBuilder.create(data)
        logger.info(json.dumps(jwts, indent=2))
        assert 'access' in jwts.keys()
        assert 'refresh' in jwts.keys()
