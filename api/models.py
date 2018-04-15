from django.db import models

# Create your models here.
class Score(models.Model):
    filename = models.CharField(max_length=100, unique=True)
    runtime = models.FloatField(max_length=10000, null=False)
    metric2 = models.FloatField(max_length=10000, null=False)
    metric3 = models.FloatField(max_length=10000, null=False)