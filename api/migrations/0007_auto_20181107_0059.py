# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2018-11-07 00:59
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_auto_20181106_1844'),
    ]

    operations = [
        migrations.AlterField(
            model_name='score_r2',
            name='bucket',
            field=models.CharField(max_length=100),
        ),
    ]
