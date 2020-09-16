from django.contrib import admin

from . models import JWTConnectAuthToken


@admin.register(JWTConnectAuthToken)
class JWTConnectAuthTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'issued_at', 
                    'access_expire_at', 'refresh_expire_at')
    list_filter = ('issued_at', 'is_active',
                   'access_expire_at', 'refresh_expire_at')
    search_fields = ('user', 'access_jti', 'refresh_jti',)
