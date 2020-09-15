from django.conf import settings
from django.db.models import Q
from django.utils.translation import gettext as _

from django.shortcuts import render
from rest_framework import generics, viewsets, permissions
from rest_framework.response import Response


from . models import *
# from . permissions import *
from . serializers import *


class TokenIntrospection(generics.ListAPIView):
    http_method_names = ['get', 'head']
    permission_classes = [permissions.IsAuthenticated]
    description = _('Token Introspection')
    queryset = JWTConnectAuthToken.objects.filter(is_active=True)
    serializer_class = JWTConnectAuthTokenIntrospectionSerializer

    def get_queryset(self):
        # token = self.request.query_params.get('token')
        # do not pass real tokens in GET parameters!
        # self.queryset.filter(Q(access_token=token)|Q(refresh_token=token))
        jti = self.request.query_params.get('jti')
        if not jti:
            return self.queryset.none()

        queryset = self.queryset.filter(jti=jti)
        return queryset


@api_view(['GET', 'POST'])
def token_refresh(request):
    """
    Token Refresh endpoint
    """
    
    refresh_token = request.GET.get('refresh_token') or \
                    request.POST.get('refresh_token')
    
    if refresh_token:
        jwt_store = self.queryset.filter(refresh_token=refresh_token).first()
        if not jwt_store.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        new_jwt_store = JWTConnectAuthToken ...
        
        serializer = SnippetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TokenRefresh(APIView):
    http_method_names = ['get', 'head', 'post']
    permission_classes = [permissions.IsAuthenticated]
    description = _('Token Refresh')
    #lookup_field = 'token'
    queryset = JWTConnectAuthToken.objects.filter(is_active=True)
    serializer_class = JWTConnectAuthTokenSerializer

    def get_queryset(self):
        refresh_token = self.request.query_params.get('token')
        if not refresh_token:
            return self.queryset.none()
        
        
        if not jwt_store.is_valid():
            return self.queryset.none()
        
        return queryset
