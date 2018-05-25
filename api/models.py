from django.db import models

# Create your models here.
class Score(models.Model):
    filename = models.CharField(max_length=100, unique=True)
    runtime = models.FloatField(max_length=10000, null=False)
    acc_clf = models.FloatField(max_length=10000, null=False)
    acc = models.FloatField(max_length=10000, null=False)
    n_clf = models.FloatField(max_length=10000, null=False)
    acc_over_time = models.FloatField(max_length=10000, null=False)
