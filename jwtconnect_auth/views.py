from django.conf import settings
from django.db.models import Q
from django.utils.translation import gettext as _

from django.shortcuts import render
from rest_framework import generics, viewsets, permissions

from . models import *
# from . permissions import *
from . serializers import *


class TokenIntrospection(generics.ListCreateAPIView):
    http_method_names = ['get', 'head']
    # permission_classes = [permissions.DjangoModelPermissionsOrAnonReadOnly]
    description = _('Token Introspection')
    queryset = JWTConnectAuthToken.objects.filter(is_active=True)
    serializer_class = JWTConnectAuthTokenSerializer

    def get_queryset(self):
        # token = self.request.query_params.get('token')
        # do not pass real tokens in GET parameters!
        # self.queryset.filter(Q(access_token=token)|Q(refresh_token=token))
        jti = self.request.query_params.get('jti')
        if not jti:
            return self.queryset.none()

        queryset = self.queryset.filter(jti=jti)
        return queryset
