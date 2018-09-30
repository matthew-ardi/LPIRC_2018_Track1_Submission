"""
Django settings for LPIRC_2018_Track3_Submission project.

Generated by 'django-admin startproject' using Django 1.11.2.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os, sys, dj_database_url

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BASE_DIR =  os.path.dirname(PROJECT_ROOT)

# Environment Variables Import
PRODUCTION = True

try:
    REFEREE = os.environ['REFEREE']
    ALLOWED_USER = os.environ['ALLOWED_USER']
    ALLOWED_USER_PASSWORD = os.environ['ALLOWED_USER_PASSWORD']
    ALLOWED_USER2 = os.environ['ALLOWED_USER2']
    ALLOWED_USER_PASSWORD2 = os.environ['ALLOWED_USER_PASSWORD2']
    # Does the site runs on production site or tested locally
    # SECURITY WARNING: keep the secret key used in production secret!
    SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
    # Database URLS
    #DATABASE_URL = os.environ["DATABASE_URL"]

    # Recaptcha Keys
    GOOGLE_RECAPTCHA_SECRET_KEY = os.environ['RECAPTCHA_SECRET_KEY']
    GOOGLE_RECAPTCHA_SITE_KEY = os.environ['RECAPTCHA_SITE_KEY']

    # Github Auth
    SOCIAL_AUTH_GITHUB_KEY = os.environ['GITHUB_KEY']
    SOCIAL_AUTH_GITHUB_SECRET = os.environ['GITHUB_SECRET']

    SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ['GOOGLE_LOGIN_KEY']
    SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ['GOOGLE_LOGIN_SECRET']
    # Email Smtp Settings
    EMAIL_HOST = os.environ['EMAIL_HOST']
    EMAIL_PORT = os.environ['EMAIL_PORT']
    EMAIL_HOST_USER = os.environ['EMAIL_HOST_USER']
    EMAIL_HOST_PASSWORD = os.environ['EMAIL_HOST_PASSWORD']
    EMAIL_USE_TLS = True
    # Email backend
    # send email through smtp
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend' if PRODUCTION\
        else 'django.core.mail.backends.console.EmailBackend'
    # show email on console
except KeyError as e:
    print('Lacking Environment Variables: ' + str(e))
    exit()


# Quick-start development settings - unsuitable for production

# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False if PRODUCTION else True

ALLOWED_HOSTS = ['*']

# Setup for proxy
USE_X_FORWARDED_HOST=True

# Application definition

INSTALLED_APPS = [
    'app',
    'api',
    'rest_framework',
    'social_django',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'wagtail.contrib.forms',
    'wagtail.contrib.redirects',
    'wagtail.embeds',
    'wagtail.sites',
    'wagtail.users',
    'wagtail.snippets',
    'wagtail.documents',
    'wagtail.images',
    'wagtail.search',
    'wagtail.admin',
    'wagtail.core',

    'modelcluster',
    'taggit',
]

MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'wagtail.core.middleware.SiteMiddleware',
'wagtail.contrib.redirects.middleware.RedirectMiddleware',
]

ROOT_URLCONF = 'LPIRC_2018_Track3_Submission.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]


WSGI_APPLICATION = 'LPIRC_2018_Track3_Submission.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Social oAuth
AUTHENTICATION_BACKENDS = (
    'social_core.backends.github.GithubOAuth2',

    'social_core.backends.open_id.OpenIdAuth',  # for Google authentication
    'social_core.backends.google.GoogleOpenId',  # for Google authentication
    'social_core.backends.google.GoogleOAuth2',

    'django.contrib.auth.backends.ModelBackend',
)
LOGIN_URL = 'index'
LOGOUT_URL = 'logout'
LOGIN_REDIRECT_URL = 'redirect_login'

SOCIAL_AUTH_LOGIN_ERROR_URL = '/social_login_error/'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = 'index'
SOCIAL_AUTH_RAISE_EXCEPTIONS = False
# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'app/static/app'),
)
STATIC_ROOT = os.path.join(PROJECT_ROOT, 'static')

MEDIA_URL = '/submissions/'
MEDIA_ROOT = os.path.join(BASE_DIR, "submissions/")

# Wagtail Configs
WAGTAIL_SITE_NAME = 'LPIRC 2018 cms'