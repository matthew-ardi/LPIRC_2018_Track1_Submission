# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-02-20 00:09
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='registeruser',
            name='contract_signed',
            field=models.BooleanField(default=False),
        ),
    ]
