from django.contrib import admin
from django.urls import path

from . views import *

urlpatterns = []

urlpatterns += path('token/introspection', TokenIntrospection.as_view()),
