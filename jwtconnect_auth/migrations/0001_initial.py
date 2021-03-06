# Generated by Django 3.1.1 on 2020-09-14 21:52

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='JWTConnectAuthToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.TextField(help_text='Token')),
                ('refresh_token', models.TextField(help_text='Refresh Token')),
                ('issued_at', models.DateTimeField(help_text='Issued At')),
                ('expire_at', models.DateTimeField(help_text='Expire at')),
                ('audience', models.CharField(blank=True, help_text='Audience, recipients that the JWT isintended for. Multiple service/resource name for whom have been released', max_length=256, null=True)),
                ('sid', models.CharField(blank=True, max_length=256, null=True, verbose_name='Django Session id')),
                ('sub', models.CharField(blank=True, max_length=256, null=True, verbose_name='Django opaque user identifier')),
                ('jti', models.CharField(blank=True, max_length=256, null=True, verbose_name='Unique identifier for this token')),
                ('is_active', models.BooleanField(default=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Token',
                'verbose_name_plural': 'Tokens',
            },
        ),
    ]
