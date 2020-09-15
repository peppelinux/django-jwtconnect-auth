from rest_framework import serializers

from . models import *


class JWTConnectAuthTokenIntrospectionSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = JWTConnectAuthToken
        #  fields = '__all__'
        fields = ['jti', 'exp', 'iat', 'sub', 'aud',
                  'expire_at', 'issued_at']
    
