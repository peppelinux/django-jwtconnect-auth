from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.db.models import Q
from django.utils.translation import gettext as _

from django.shortcuts import render
from rest_framework import generics, viewsets, permissions, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from . actions import remove_older_tokens
from . authentication import JWTConnectAuthBearer
from . models import *
# from . permissions import *
from . serializers import *


HTTP_403_FORBIDDEN_RESPONSE = Response({'error': 'invalid_request', 
                                        'error_description': "please go away"}, 
                                        status=status.HTTP_403_FORBIDDEN)
HTTP_401_UNAUTHORIZED_RESPONSE = Response({'error': 'invalid_token',
                                           'error_description': 'token_expired or not existent'}, 
                                           status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def token_introspection(request):
    """
    get "token" or "jti", return meta informations about the inspected token
    """
    if not JWTConnectAuthBearer().authenticate(request):
        return HTTP_403_FORBIDDEN_RESPONSE
    
    value = request.data.get('token') or request.data.get('jti')
    jwt_store = JWTConnectAuthToken.objects.filter(is_active=True).\
                                            filter(Q(refresh_jti=value)| \
                                                   Q(access_jti=value)| \
                                                   Q(refresh_token=value)| \
                                                   Q(access_token=value)).first()
    if jwt_store:
        if value in (jwt_store.access_token, jwt_store.access_jti):
            jti = jwt_store.access_jti
            exp =  jwt_store.access_exp
            expire_at = jwt_store.access_expire_at
        else:
            jti = jwt_store.refresh_jti
            exp =  jwt_store.refresh_exp
            expire_at = jwt_store.refresh_expire_at
        
        data = dict(jti = jti,
                    iat = jwt_store.iat,
                    issued_at = jwt_store.issued_at,
                    exp = exp,
                    expire_at = expire_at,
                    sub = jwt_store.sub,
                    aud = jwt_store.aud)
        return Response(data, status=status.HTTP_200_OK)
    
    return HTTP_401_UNAUTHORIZED_RESPONSE


@api_view(['POST'])
def token_refresh(request):
    """
    Token Refresh endpoint
    """
    refresh_token = request.data.get('token')
    if refresh_token:
        jwt_store = JWTConnectAuthToken.objects.filter(is_active=True, 
                                                       refresh_token=refresh_token).first()
        if not jwt_store or jwt_store.is_refresh_expired():
            return HTTP_401_UNAUTHORIZED_RESPONSE
        
        new_jwt_data = JWTConnectAuthTokenBuilder.build(jwt_store.user)
        new_jwt_enc = {k:v 
                       for k,v in JWTConnectAuthTokenBuilder.create(new_jwt_data).items() 
                       if k in ('access_token', 'refresh_token')}
        
        kwargs = dict(user = jwt_store.user)
        kwargs.update(**new_jwt_enc)
        new_jwt_store = JWTConnectAuthToken.objects.create(**kwargs)
        if not getattr(settings, 'JWTAUTH_MULTIPLE_TOKENS', True):
            remove_older_tokens(user=jwt_store.user)
        return Response(new_jwt_enc, status=status.HTTP_201_CREATED)
    
    return Response({'error': 'invalid_request', 
                     'error_description': "not eligible for renewal"}, 
                     status=status.HTTP_400_BAD_REQUEST)
