from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.
class Score(models.Model):
    filename = models.CharField(max_length=100, unique=True)
    runtime = models.FloatField(max_length=10000, null=False)
    acc_clf = models.FloatField(max_length=10000, null=False)
    acc = models.FloatField(max_length=10000, null=False)
    n_clf = models.FloatField(max_length=10000, null=True)
    acc_over_time = models.FloatField(max_length=10000, null=True)
    message = models.CharField(max_length=10000, default="Not Provided")

class Score_r2(models.Model):
    filename = models.CharField(max_length=100, unique=True)
    runtime = models.FloatField(max_length=10000, null=False)
    acc_clf = models.FloatField(max_length=10000, null=False)
    acc = models.FloatField(max_length=10000, null=False)
    n_clf = models.FloatField(max_length=10000, null=True)
    acc_over_time = models.FloatField(max_length=10000, null=True)
    ref_acc = models.FloatField(max_length=10000, null=True)
    bucket = models.CharField(max_length=100)
    metric = models.FloatField(max_length=10000, null=True)
    message = models.CharField(max_length=10000, default="Not Provided")

class Score_r2_detection(models.Model):
    filename = models.CharField(max_length=100, unique=True)
    runtime = models.FloatField(max_length=10000, null=False)
    map_over_time = models.FloatField(max_length=10000, null=False)
    map_of_processed = models.FloatField(max_length=10000, null=False)
    message = models.CharField(max_length=10000, default="Not Provided")