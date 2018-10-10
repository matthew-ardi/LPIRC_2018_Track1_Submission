from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib import admin, messages

# import for wagtail
from modelcluster.fields import ParentalKey

from wagtail.core.models import Page, Orderable
from wagtail.core.fields import RichTextField
from wagtail.admin.edit_handlers import FieldPanel, MultiFieldPanel, InlinePanel
from wagtail.images.edit_handlers import ImageChooserPanel
from wagtail.search import index

# Create your models here.
class RegisterUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_confirmed = models.BooleanField(default=False)
    contract_signed = models.BooleanField(default=False)


class FooterBio(models.Model):

    def clean(self):
        if not self.pk and MyModel.objects.filter(user=self.user, is_active=True).exists():
            raise ValidationError('How about no?')

    title = models.CharField(verbose_name='Footer Bio', max_length = 25, blank = False)
    content = models.CharField(verbose_name='Footer Content', max_length = 3000, blank = False)

    def __str__(self):
        return "{0}".format(self.title)
    
@receiver(post_save, sender=User)
def update_user_registeruser(sender, instance, created, **kwargs):
    if created:
        RegisterUser.objects.create(user=instance)
    instance.registeruser.save()

class Tfile1(models.Model):
    user = models.OneToOneField(User, on_delete=models.DO_NOTHING)
    fn = models.CharField(max_length=1000)
    def __str__(self):
        return "{0}".format(self.user)

class Tfile2(models.Model):
	user = models.OneToOneField(User, on_delete=models.DO_NOTHING)
	fn = models.CharField(max_length=1000)

class Sponsor(models.Model):
    title = models.CharField(verbose_name='Footer Bio', max_length = 25, blank = False)
    image_link = models.CharField(verbose_name='image link', max_length = 2000, blank = False)
    redirect_link = models.CharField(verbose_name='image link', max_length = 2000, blank = True) 
    def __str__(self):
        return "{0}".format(self.title)

class Organizer(models.Model):
    title = models.CharField(verbose_name='Footer Bio', max_length = 25, blank = False)
    image_link = models.CharField(verbose_name='image link', max_length = 2000, blank = False) 
    redirect_link = models.CharField(verbose_name='image link', max_length = 2000, blank = True) 
    def __str__(self):
        return "{0}".format(self.title)

# Wagtail models
class BlogPage(Page):

    # Database fields

    body = RichTextField()
    date = models.DateField("Post date")
    feed_image = models.ForeignKey(
        'wagtailimages.Image',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='+'
    )


    # Search index configuration

    search_fields = Page.search_fields + [
        index.SearchField('body'),
        index.FilterField('date'),
    ]


    # Editor panels configuration

    content_panels = Page.content_panels + [
        FieldPanel('date'),
        FieldPanel('body', classname="full"),
        InlinePanel('related_links', label="Related links"),
    ]

    promote_panels = [
        MultiFieldPanel(Page.promote_panels, "Common page configuration"),
        ImageChooserPanel('feed_image'),
    ]


    # Parent page / subpage type rules

    parent_page_types = []
    subpage_types = []

class BlogPageRelatedLink(Orderable):
    page = ParentalKey(BlogPage, on_delete=models.CASCADE, related_name='related_links')
    name = models.CharField(max_length=255)
    url = models.URLField()

    panels = [
        FieldPanel('name'),
        FieldPanel('url'),
    ]

admin.site.register(FooterBio)
admin.site.register(Tfile1)