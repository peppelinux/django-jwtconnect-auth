from django.contrib import admin
from django.urls import path

from . views import *

app_name='jwtconnect_auth'

urlpatterns = []

urlpatterns += path('token/introspection', token_introspection, name='token_introspection'),
urlpatterns += path('token/refresh', token_refresh, name='token_refresh'),
