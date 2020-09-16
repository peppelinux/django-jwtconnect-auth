import copy
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
    access_expire_at = models.DateTimeField(help_text=_('Expire at'),
                                     blank=True, null=True)
    refresh_expire_at = models.DateTimeField(help_text=_('Refresh expire at'),
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
    access_jti = models.CharField(help_text=_('Unique identifier for the access token'),
                                  max_length=256, unique=True,
                                  blank=True, null=True)
    refresh_jti = models.CharField(help_text=_('Unique identifier for the refresh token'),
                                   max_length=256, unique=True,
                                   blank=True, null=True)

    is_active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')
    
    def decode_refresh(self):
        return JWTConnectAuthKeyHandler.decode_jwt(self.refresh_token)
    
    def decode_access(self):
        return JWTConnectAuthKeyHandler.decode_jwt(self.access_token)
        
    @classmethod
    def create(cls, user, **kwargs):
        kwargs['user'] = user
        data = JWTConnectAuthTokenBuilder.build(**kwargs)
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
    def access_exp(self):
        return int(self.access_expire_at.timestamp()) if self.access_expire_at else None

    @access_exp.setter
    def access_exp(self, value):
        self.access_expire_at = timezone.make_aware(datetime.datetime.fromtimestamp(value))

    @property
    def refresh_exp(self):
        return int(self.refresh_expire_at.timestamp()) if self.refresh_expire_at else None

    @refresh_exp.setter
    def refresh_exp(self, value):
        self.refresh_expire_at = timezone.make_aware(datetime.datetime.fromtimestamp(value))

    @property
    def aud(self):
        return self.audience.split(' ') if self.audience else []

    @aud.setter
    def aud(self, values: list):
        if values:
            self.aud = ' '.join(values)
            self.save()

    def is_access_expired(self):
        if self.access_expire_at <= timezone.localtime():
            return True

    def is_refresh_expired(self):
        if self.refresh_expire_at <= timezone.localtime():
            return True

    def save(self, *args, **kwargs):
        fields_name = ('iat', 'sub', 'aud')
        fields = (getattr(self, k) for k in fields_name)
        
        keyjar = JWTConnectAuthKeyHandler.keyjar()
        entry = dict()
        
        for token in (self.access_token, self.refresh_token):
            jwt = Message().from_jwt(token, keyjar=keyjar)
            if not jwt.verify():
                raise InvalidJWTSignature('Not a valid JWT: signature failed on save.')
            jwt_dict = jwt.to_dict()
            if jwt_dict['ttype'] == 'R':
                entry['refresh_expire_at'] = copy.deepcopy(jwt_dict['exp'])
                entry['refresh_jti'] = copy.deepcopy(jwt_dict['jti'])
            elif jwt_dict['ttype'] == 'T':
                entry['access_expire_at'] = copy.deepcopy(jwt_dict['exp'])
                entry['access_jti'] = copy.deepcopy(jwt_dict['jti'])
            entry.update({k:v for k,v in jwt_dict.items()})
        
        self.refresh_exp = entry['refresh_expire_at']
        self.access_exp = entry['access_expire_at']
        self.refresh_jti = entry['refresh_jti']
        self.access_jti = entry['access_jti']
        self.iat = entry['iat']
        self.sub = entry['sub']
        self.aud = entry.get('aud', [])
        super(JWTConnectAuthToken, self).save(*args, **kwargs)

    def __str__(self):
        return '{}: {}'.format(self.user, self.issued_at)
