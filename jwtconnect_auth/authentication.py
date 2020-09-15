from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext as _
from rest_framework.authentication import (BasicAuthentication,
                                           TokenAuthentication,
                                           get_authorization_header)

from rest_framework.exceptions import AuthenticationFailed

from . models import JWTConnectAuthToken


class JWTConnectAuthBearer(TokenAuthentication):

    keyword = 'Bearer'
    model = JWTConnectAuthToken
    
    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        return super(JWTConnectAuthBearer, self).authenticate(request)
    
    def authenticate_credentials(self, token):
        model = self.model
        try:
            token = model.objects.select_related('user').get(access_token=token)
        except model.DoesNotExist:
            raise AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)
