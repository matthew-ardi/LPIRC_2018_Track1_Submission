from django.conf.urls import url, include
from api import views as api_views

urlpatterns = [
    url(r'^files/$', api_views.send_zip),
    url(r'^list_files/$', api_views.list_files),
]
