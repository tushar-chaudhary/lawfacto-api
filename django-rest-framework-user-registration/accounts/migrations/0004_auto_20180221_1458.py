# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-02-21 14:58
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_profile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='user',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='otp_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='otpkey',
            field=models.CharField(blank=True, max_length=30),
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]