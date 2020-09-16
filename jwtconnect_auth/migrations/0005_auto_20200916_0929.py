# Generated by Django 3.1.1 on 2020-09-16 09:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jwtconnect_auth', '0004_auto_20200916_0912'),
    ]

    operations = [
        migrations.RenameField(
            model_name='jwtconnectauthtoken',
            old_name='jti',
            new_name='access_jti',
        ),
        migrations.AddField(
            model_name='jwtconnectauthtoken',
            name='refresh_jti',
            field=models.CharField(blank=True, help_text='Unique identifier for the refresh token', max_length=256, null=True, unique=True),
        ),
    ]
