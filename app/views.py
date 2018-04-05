import os
import json
import urllib
import sys
from django.http import HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import login, update_session_auth_hash
from django.contrib import messages
from django.conf import settings
from django.core.mail import mail_admins
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from social_django.models import UserSocialAuth
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .tokens import account_activation_token
from .forms import RegistrationForm, ProfileEmailForm
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
import pytz
import datetime
import glob
import re

# Home page
#def index(request):
#    return render(request, 'app/index.html')

def redirect_login(request):
    return render(request, 'app/redirect_login.html')

#Social Login
def oauthinfo(request):
    if request.method == 'POST':
        return redirect('index')

    else:
        user = request.user
        if user.is_active:
            return redirect('index')
        else:
            try:
                github_login = user.social_auth.get(provider='github')
            except UserSocialAuth.DoesNotExist:
                github_login = None


            return render(request, 'app/oauthinfo.html', {})


def register(request):
    if request.method == 'POST':
        form1 = RegistrationForm(request.POST)

        if form1.is_valid():

            recaptcha_response = request.POST.get('g-recaptcha-response')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            values = {
                'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            data = urllib.parse.urlencode(values).encode()
            req =  urllib.request.Request(url, data=data)
            response = urllib.request.urlopen(req)
            result = json.loads(response.read().decode())
            if result['success']:
                #model1 is the model for user
                model1 = form1.save(commit=False) #Required information of user
                model1.is_active = False #Set true for testing without email.
                model1.save()

                #Email user
                current_site = get_current_site(request)
                subject = 'Activate Your LPIRC2018 Account'
                message = render_to_string('app/confirmation_email.html', {
                    'user': model1,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(model1.pk)),
                    'token': account_activation_token.make_token(model1),
                })
                model1.email_user(subject, message)

                return redirect('email_confirmation_sent')
            else:
                messages.error(request, 'Invalid reCAPTCHA. Please confirm you are not a robot and try again.')
                sitekey = settings.GOOGLE_RECAPTCHA_SITE_KEY
        else:
            sitekey = settings.GOOGLE_RECAPTCHA_SITE_KEY
    else:
        form1 = RegistrationForm()
        sitekey = settings.GOOGLE_RECAPTCHA_SITE_KEY

    return render(request, 'app/register.html', {'form1': form1, 'sitekey': sitekey})

def email_confirmation_sent(request):
    return render(request, 'app/email_confirmation_sent.html')

def email_confirmation_invalid(request):
    return render(request, 'app/email_confirmation_invalid.html')

def account_activated(request):
    return render(request, 'app/account_activated.html')

def activate(request, uidb64, token):
    """Followed tutorial: https://simpleisbetterthancomplex.com/tutorial/2017/02/18/how-to-create-user-sign-up-view.html"""
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.registeruser.email_confirmed = True
        user.save()

        #email admin
        admin_subject = 'New User Registered'
        admin_message = render_to_string('app/new_user_email_to_admin.html', {
            'user': user,
        })
        mail_admins(admin_subject, admin_message)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        return redirect('account_activated')
    else:
        return render(request, 'email_confirmation_invalid.html')

@login_required
def profile(request):
    user = request.user
    try:
        github_login = user.social_auth.get(provider='github')
    except UserSocialAuth.DoesNotExist:
        github_login = None

    try:
        google_login = user.social_auth.get(provider='google-oauth2')
    except UserSocialAuth.DoesNotExist:
        google_login = None

    #initialize forms
    emailForm = ProfileEmailForm(instance=user)


    # Change Email
    if request.method == 'POST' and 'changeEmail' in request.POST:
        emailForm = ProfileEmailForm(request.POST, instance=user)
        if emailForm.is_valid():
            emailForm.save()
            messages.success(request, 'Your Email has been successfully updated!')
            return redirect('profile')
    else:
        emailForm=ProfileEmailForm(instance=user)
        #messages.error(request, 'Something went wrong. Please try again or contact us!')
    #return render(request, 'app/profile.html', form_dict)

    return render(request, 'app/profile.html', {
        'github_login': github_login,
        'google_login': google_login,
        'emailForm': emailForm,
    })


def privacy(request):
    return render(request, 'app/privacy.html')

def rules(request):
    return render(request, 'app/rules.html')

def terms(request):
    return render(request, 'app/terms.html')
def terms2(request):
    return render(request, 'app/terms2.html')

def social_login_error(request):
    return render(request, 'app/social_login_error.html')

@login_required
def simple_upload(request):
    user = request.user
    if user.registeruser.contract_signed == False:
        return redirect('index')

    try:
        if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            
        if myfile.name[-6:] != ".tfile":
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Submission Failure: File format must be .tfile"
        })
        if str(myfile.name[:-6]) != str(request.user.username):
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Submission Failure: File name must be the log-in name"
        })
        fs = FileSystemStorage(location='upload_files/')
        tz = pytz.timezone('America/New_York')
        now = datetime.datetime.now(tz)
        name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}.tfile".format(myfile.name[:-6], now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)
        for i in glob.glob('upload_files/*'):
             l = len(str(request.user.username))
             if i[13:(13+l)] == str(request.user.username)：
                 day = re.findall(r'-(\w+-\w+)-\w+:',i[l-1:])
                 day_now = "{0}-{1}".format(now.month,now.day)
                 if (day != []):
                    if (day[0] == day_now):
                       return render(request, 'app/simple_upload.html', {
            'wrong_file': "Submission Failure: One submission per day"})
        filename = fs.save(name, myfile)
        uploaded_file_url = fs.url(filename)
        return render(request, 'app/simple_upload.html', {
            'uploaded_file_url': myfile.name
        })
      
    except:
        return render(request, 'app/simple_upload.html')


@staff_member_required
def admin_email(request):
    # obtain user id list from session, or none
    user_selected = request.session.get('user_id_selected', None)

    # generate email list based on user ids
    email_list =""
    if user_selected is not None:
        for i in user_selected:
            obj = User.objects.get(id=i)
            if obj.email != '':
                email_list = email_list + ',' + str(obj.email)

    return HttpResponse(email_list[1:])
