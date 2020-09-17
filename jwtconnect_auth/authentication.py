import logging

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext as _
from rest_framework.authentication import (BasicAuthentication,
                                           TokenAuthentication,
                                           get_authorization_header)

from rest_framework.exceptions import AuthenticationFailed

from . models import JWTConnectAuthToken
from . settings import *

logger = logging.getLogger('__name__')

JWTAUTH_AUTH_HEADER_TYPES = getattr(settings, 'JWTAUTH_AUTH_HEADER_TYPES',
                                    DEFAULT_JWTAUTH_AUTH_HEADER_TYPES)


class JWTConnectAuthBearer(TokenAuthentication):

    keyword = 'Bearer'
    model = JWTConnectAuthToken
    
    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].decode() not in JWTAUTH_AUTH_HEADER_TYPES:
            return None
        return super(JWTConnectAuthBearer, self).authenticate(request)
    
    def authenticate_credentials(self, token):
        model = self.model
        try:
            token = model.objects.select_related('user').get(access_token=token)
        except model.DoesNotExist: # pragma: no cover
            logger.warning(AuthenticationFailed(_('Invalid token.')))
            return None

        if not token.user.is_active: # pragma: no cover
            logger.warning(AuthenticationFailed(_('User inactive or deleted.')))
            return None
        
        if token.is_access_expired(): # pragma: no cover
            logger.warning(AuthenticationFailed(_('Token expired.')))
            return None

        return (token.user, token)
