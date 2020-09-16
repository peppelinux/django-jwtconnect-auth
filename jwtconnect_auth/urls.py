from django.contrib import admin
from django.urls import path

from . views import *

urlpatterns = []

urlpatterns += path('token/introspection', token_introspection),
urlpatterns += path('token/refresh', token_refresh),
