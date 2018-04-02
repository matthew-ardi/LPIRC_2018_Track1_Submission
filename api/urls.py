from django.conf.urls import url, include
from api import views as api_views

urlpatterns = [
    url(r'^files/$', api_views.send_zip),
    url(r'^list_files/$', api_views.list_files),
    url(r'^get_file/(?P<requested_file>[\s\S]+)/$', api_views.get_file),
    url(r'^post/$', api_views.post),
]