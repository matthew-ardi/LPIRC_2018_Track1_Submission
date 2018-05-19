"""LPIRC_2018_Track3_Submission URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from . import views as app_views
from django.contrib.auth import views as auth_views

urlpatterns = [
    #url(r'^$', app_views.index, name="index"),
    url(r'^$', auth_views.login, {'template_name': 'app/index.html'}, name='index'),
    url(r'^register/$', app_views.register, name='register'),
    #url(r'^login/$', auth_views.login, {'template_name': 'app/login.html'}, name='login'),
    url(r'^redirect_login/$', app_views.redirect_login, name='redirect_login'),
    url(r'^logout/$', auth_views.logout, {'next_page': '/'}),
    url(r'^admin_email/$', app_views.admin_email, name='admin_email'),

    #reset password
    url(r'^password_reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password_reset_email_sent/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),

    #social oAuth
    url(r'^oauth/', include('social_django.urls', namespace='social')),
    url(r'^social_login_error/', app_views.social_login_error, name='social_login_error'),
    #url(r'^oauthinfo/$', app_views.oauthinfo, name='more info'),

    #email confirmation for registration
    url(r'^email_confirmation_sent/$', app_views.email_confirmation_sent, name='email_confirmation_sent'),
    url(r'^email_confirmation_invalid/$', app_views.email_confirmation_invalid, name='email_confirmation_invalid'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
    app_views.activate, name='activate'),
    url(r'^account_activated/$', app_views.account_activated, name='account_activated'),

    #profile
    url(r'^profile/$', app_views.profile, name='profile'),

    #upload
    url(r'^simple_upload/$', app_views.simple_upload, name='simple_upload'),

    #score board
    url(r'^score_board/$', app_views.score_board, name='score_board'),

    #terms and policies
    url(r'^terms/$', app_views.terms, name='terms'),
    url(r'^terms2/$', app_views.terms2, name='terms2'),
    url(r'^privacy/$', app_views.privacy, name='privacy'),
    url(r'^track1_info/$', app_views.track1_info, name='track1_info'),
    url(r'^track2_info/$', app_views.track2_info, name='track2_info'),
    url(r'^track2/$', app_views.track2, name='track2'),
]
