from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_score_message'),
    ]

    operations = [
        migrations.CreateModel(
            name='Score_r2',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filename', models.CharField(max_length=100, unique=True)),
                ('runtime', models.FloatField(max_length=10000)),
                ('acc_clf', models.FloatField(max_length=10000)),
                ('acc', models.FloatField(max_length=10000)),
                ('n_clf', models.FloatField(max_length=10000, null=True)),
                ('acc_over_time', models.FloatField(max_length=10000, null=True)),
                ('message', models.CharField(default='Not Provided', max_length=10000)),
            ],
        ),
    ]