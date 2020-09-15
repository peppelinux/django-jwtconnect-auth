from django.contrib import admin

from . models import JWTConnectAuthToken


@admin.register(JWTConnectAuthToken)
class JWTConnectAuthTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'issued_at', 'expire_at')
    list_filter = ('issued_at', 'expire_at', 'is_active')
    search_fields = ('user', 'access_token', 'refresh_token')
