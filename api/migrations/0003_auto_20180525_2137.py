# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2018-05-25 21:37
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_auto_20180518_1945'),
    ]

    operations = [
        migrations.AddField(
            model_name='score',
            name='acc_over_time',
            field=models.FloatField(max_length=10000, null=True),
        ),
        migrations.AddField(
            model_name='score',
            name='n_clf',
            field=models.FloatField(max_length=10000, null=True),
        ),
    ]
