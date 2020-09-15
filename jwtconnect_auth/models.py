import datetime
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext as _

from . exceptions import InvalidJWTSignature
from . jwks import *


logger = logging.getLogger('__name__')


class JWTConnectAuthToken(models.Model):
    """
    """
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    access_token = models.TextField(help_text=_('Token'), unique=True)
    refresh_token = models.TextField(help_text=_('Refresh Token'),
                                     unique=True)
    issued_at = models.DateTimeField(help_text=_('Issued At'),
                                     blank=True, null=True)
    expire_at = models.DateTimeField(help_text=_('Expire at'),
                                     blank=True, null=True)

    # optionals
    audience = models.CharField('aud',
                                help_text=_('Audience, recipients that the JWT is'
                                            'intended for. Multiple service/resource '
                                            'name for whom have been released'),
                                max_length=256, blank=True, null=True)
    sid = models.CharField(help_text=_('Django Session id'), max_length=256,
                           blank=True, null=True)
    sub = models.CharField(help_text=_('Django opaque user identifier'),
                           max_length=256,
                           blank=True, null=True)
    jti = models.CharField(help_text=_('Unique identifier for this token'),
                           max_length=256, unique=True,
                           blank=True, null=True)

    is_active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')
    
    @classmethod
    def create(cls, user, **kwargs):
        kwargs['user'] = user
        data = JWTConnectAuthTokenBuilder.build(**kwargs)
        breakpoint()
        jwts = JWTConnectAuthTokenBuilder.create(data, **kwargs)
        kwargs.update(jwts)
        return cls.objects.create(**kwargs)
        
    
    @property
    def iat(self):
        return int(self.issued_at.timestamp()) if self.issued_at else None

    @iat.setter
    def iat(self, value):
        self.issued_at = timezone.make_aware(datetime.datetime.fromtimestamp(value))

    @property
    def exp(self):
        return int(self.expire_at.timestamp()) if self.expire_at else None

    @exp.setter
    def exp(self, value):
        self.expire_at = timezone.make_aware(datetime.datetime.fromtimestamp(value))

    @property
    def aud(self):
        return self.audience.split(' ') if self.audience else []

    @aud.setter
    def aud(self, values: list):
        self.aud = ' '.join(values)
        self.save()

    def is_expired(self):
        if self.expire_at > timezone.localtime():
            return True

    def save(self, *args, **kwargs):
        fields_name = ('jti', 'iat', 'exp', 'sub', 'aud')
        fields = (getattr(self, k) for k in fields_name)
        if not all(fields):
            keyjar = JWTConnectAuthKeyHandler.keyjar()
            for token in (self.access_token, self.refresh_token):
                jwt = Message().from_jwt(token, keyjar=keyjar)
                if not jwt.verify():
                    raise InvalidJWTSignature('Not a valid JWT: signature failed on save.')
            entry = jwt.to_dict()
            for field in fields_name:
                if not entry.get(field): continue
                setattr(self, field, entry[field])
        super(JWTConnectAuthToken, self).save(*args, **kwargs)

    def __str__(self):
        return '{}: {}'.format(self.user, self.jti)
