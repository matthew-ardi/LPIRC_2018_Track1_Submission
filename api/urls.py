from django.conf.urls import url, include
from api import views as api_views

urlpatterns = [
    url(r'^files/$', api_views.send_zip),

    url(r'^list_files1/$', api_views.list_files1),
    url(r'^get_file1/(?P<requested_file>[\s\S]+)$', api_views.get_file1),
    url(r'^listFiles1/$', api_views.listFiles1),
    url(r'^getFile1/(?P<requested_file>[\s\S]+)$', api_views.getFile1),

    url(r'^list_files2/$', api_views.list_files2),
    url(r'^get_file2/(?P<requested_file>[\s\S]+)$', api_views.get_file2),
    url(r'^listFiles2/$', api_views.listFiles2),
    url(r'^getFile2/(?P<requested_file>[\s\S]+)$', api_views.getFile2),

    url(r'^postScore/$', api_views.postScore),
    url(r'^getScore/(?P<requested_file>[\s\S]+)$', api_views.getScore),

    # API for round 2 - track 1 (Google Collaboration)
    url(r'^r2_list_track1_classification/$', api_views.r2_list_track1_classification),
    url(r'^r2_list_track1_detection/$', api_views.r2_list_track1_detection),
    url(r'^get_file1_r2_classification/(?P<requested_file>[\s\S]+)$', api_views.get_file1_r2_classification),
    url(r'^get_file1_r2_detection/(?P<requested_file>[\s\S]+)$', api_views.get_file1_r2_detection),

]

