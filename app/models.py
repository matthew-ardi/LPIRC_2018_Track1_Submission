from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

# Create your models here.
class RegisterUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_confirmed = models.BooleanField(default=False)
    contract_signed = models.BooleanField(default=False)
    
@receiver(post_save, sender=User)
def update_user_registeruser(sender, instance, created, **kwargs):
    if created:
        RegisterUser.objects.create(user=instance)
    instance.registeruser.save()

class Tfile1(models.Model):
	user = models.OneToOneField(User)
	fn = models.CharField(max_length=100)
class Tfile2(models.Model):
	user = models.OneToOneField(User)
	fn = models.CharField(max_length=100)