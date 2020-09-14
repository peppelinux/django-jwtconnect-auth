import datetime
import logging


from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext as _

from . jwks import *


logger = logging.getLogger('__name__')        


class JWTConnectAuthToken(models.Model):
    """
    """
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    token = models.TextField(help_text=_('Token'))
    refresh_token = models.TextField(help_text=_('Refresh Token'))
    issued_at = models.DateTimeField(help_text=_('Issued At'))
    expire_at = models.DateTimeField(help_text=_('Expire at'))
    
    # optionals
    audience = models.CharField(help_text=_('Audience, recipients that the JWT is'
                                            'intended for. Multiple service/resource '
                                            'name for whom have been released'),
                                max_length=256, blank=True, null=True)
    sid = models.CharField(_('Django Session id'), max_length=256,
                           blank=True, null=True)
    sub = models.CharField(_('Django opaque user identifier'), 
                           max_length=256,
                           blank=True, null=True)
    jti = models.CharField(_('Unique identifier for this token'), 
                           max_length=256,
                           blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    
    @property
    def iat(self):
        return self.issued_at.timestamp()

    @property
    def exp(self):
        return self.expire_at.timestamp()
    
    @property
    def aud(self):
        return self.audience.split(' ')

    @aud.setter
    def aud(self, values: list):
        self.aud = ' '.join(values)
        self.save()
    
    def is_expired(self):
        pass
    
    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')
    
    def __str__(self):
        return '{}: {}'.format(self.user, self.token)
