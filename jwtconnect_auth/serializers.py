from rest_framework import serializers

from . models import *


# deprecated
# class JWTConnectAuthTokenIntrospectionSerializer(serializers.HyperlinkedModelSerializer):

    # class Meta:
        # model = JWTConnectAuthToken
        # fields = ['iat', 'sub', 'aud', 'issued_at', 
                  # 'access_expire_at', 'refresh_expire_at']
    
