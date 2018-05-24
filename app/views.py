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
import logging

from django.core.mail import send_mail
from api.models import Score
from app.models import Tfile1
from app.models import Tfile2
from hashlib import sha224 as hashfunction
import logging
import ast


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

def track1_info(request):
    return render(request, 'app/track1_info.html')

def track2_info(request):
    return render(request, 'app/track2_info.html')

def general_faq(request):
    return render(request, 'app/general_faq.html')

def track2(request):
#    return render(request, 'app/track2.html')
    return redirect('https://engineering.purdue.edu/people/bo.fu.1')

def terms(request):
    return render(request, 'app/terms.html')
def terms2(request):
    return render(request, 'app/terms2.html')

def social_login_error(request):
    return render(request, 'app/social_login_error.html')

@login_required
def simple_upload(request):

    user = request.user
    #if user.registeruser.contract_signed == False:
        #return redirect('index')

    try:
        if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
        if myfile.name[-5:] != ".lite":
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Track 1 Submission Failure: File format must be .lite"
        })
        if str(myfile.name[:-5]) != str(request.user.username):
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Track 1 Submission Failure: File name must be the log-in name"
        })
        fs1= FileSystemStorage(location='upload/')
        tz = pytz.timezone('America/New_York')
        now = datetime.datetime.now(tz)
        name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(myfile.name[:-5], now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)


        for i in glob.glob('upload/*'):
             l = len(str(request.user.username))
             nm = re.search(r'^(\w+)-2018-', i[7:])
             nm = nm.group()
             if nm[:-6] == str(request.user.username):
                 day = re.findall(r'-(\w+-\w+)-\w+:',i[l-1:])
                 day_now = "{0}-{1}".format(now.month,now.day)
                 logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                 logging.debug('This is the day_now : ' + nm)
                 if (day != []):
                    #return render(request, 'app/simple_upload.html', {
            #'wrong_file': "{} {}".format(day[0],day_now)})
                    if (day[0] == day_now):

                       return render(request, 'app/simple_upload.html', {
            'wrong_file': "Track 1 Submission Failure: One submission per day"})


        # file upload process by chunks to save system's memory
        with open('upload/'+name+".lite", 'wb+') as destination:
            for chunk in myfile.chunks():
                destination.write(chunk)

        fs = FileSystemStorage(location='submissions_track1/')
        hash_of_filename = hashfunction(name.encode('utf-8')).hexdigest()
        hash_of_filename = hash_of_filename + ".lite"
        nameStore = name + ".lite"




        try:
            with open('hash_to_originalfilename.json', "r") as jsonFile:
                jsonFile.close()

        except Exception as exc:

            with open('hash_to_originalfilename.json', "w") as jsonFile:
                json.dump({}, jsonFile, indent=2)
                jsonFile.close()

        with open('hash_to_originalfilename.json', "r+") as jsonFile:
            data = json.load(jsonFile)
            data[hash_of_filename] = nameStore
            jsonFile.seek(0)
            json.dump(data, jsonFile, indent=2)
            jsonFile.truncate()


        # file upload process by chunks to save system's memory
        with open('submissions_track1/'+hash_of_filename, 'wb+') as destination:
            for chunk in myfile.chunks():
                destination.write(chunk)


        try:
            newFileName = name+".lite"
            filenameModel, created = Tfile1.objects.get_or_create(
                user = user,
                defaults={"fn":newFileName}
            )
            if not created:
                nameString = filenameModel.fn
                nameString = nameString+" "+newFileName
                filenameModel.fn = nameString
            filenameModel.save()

        except Exception as ex:
            return render(request, 'app/simple_upload.html', {
                'wrong_file': ex
            })

        return render(request, 'app/simple_upload.html', {
            'uploaded_file_url': myfile.name + " has been successfully submitted"
        })

    except:
        try:
            if request.method == 'POST' and request.FILES['myfile2']:
                myfile = request.FILES['myfile2']
            if myfile.name[-5:] != ".lite":
                return render(request, 'app/simple_upload.html', {

               'wrong_file2': "Track 2 Submission Failure: File format must be .lite"

            })
            if str(myfile.name[:-5]) != str(request.user.username):
                return render(request, 'app/simple_upload.html', {
                'wrong_file2': "Track 2 Submission Failure: File name must be the log-in name!"
            })
            fs = FileSystemStorage(location='submissions_track2/')

            fs1= FileSystemStorage(location='upload2/')
            tz = pytz.timezone('America/New_York')
            now = datetime.datetime.now(tz)
            name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(myfile.name[:-5], now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)

            for i in glob.glob('upload2/*'):
                l = len(str(request.user.username))
                nm = re.search(r'^(\w+)-2018-', i[8:])
                nm = nm.group()
                if nm[:-6] == str(request.user.username):
                    day = re.findall(r'-(\w+-\w+)-\w+:',i[l-1:])
                    day_now = "{0}-{1}".format(now.month,now.day)
                    if (day != []):
                    #return render(request, 'app/simple_upload.html', {
            #'wrong_file': "{} {}".format(day[0],day_now)})


                         if (day[0] == day_now):
                               return render(request, 'app/simple_upload.html', {
                               'wrong_file2': "Submission Failure: One submission per day"})



            # file upload process by chunks to save system's memory
            with open('upload2/'+name+".lite", 'wb+') as destination:
                for chunk in myfile.chunks():
                    destination.write(chunk)


        # to anonymise the username
        # used sha512 hash
        # new filename is a hash in hex format
        # map of hash to filename is appended to file hash_to_originalfilename.json in the root directory
            # hash_of_filename = hashfunction(name.encode('utf-8')).hexdigest()
            # with open('hash_to_originalfilename.json', "a+") as writeJSON:
            #     json.dump({hash_of_filename: name}, writeJSON, indent=2)
            # hash_of_filename = hash_of_filename + ".tfile"


            hash_of_filename = hashfunction(name.encode('utf-8')).hexdigest()

            hash_of_filename = hash_of_filename + ".lite"
            nameStore = name + ".lite"

            try:
                with open('hash_to_originalfilename.json', "r") as jsonFile:
                    jsonFile.close()

            except Exception as exc:

                with open('hash_to_originalfilename.json', "w") as jsonFile:
                    json.dump({}, jsonFile, indent=2)
                    jsonFile.close()

            with open('hash_to_originalfilename.json', "r+") as jsonFile:
                data = json.load(jsonFile)
                data[hash_of_filename] = nameStore
                jsonFile.seek(0)
                json.dump(data, jsonFile, indent=2)
                jsonFile.truncate()


            # file upload process by chunks to save system's memory
            with open('submissions_track2/'+hash_of_filename, 'wb+') as destination:
                for chunk in myfile.chunks():
                    destination.write(chunk)

            try:
                u = Tfile2.objects.get(user=user)
                u.delete()
            except:
                t = 0
            us = Tfile2(user=user, fn=nameStore)
            us.save()


            return render(request, 'app/simple_upload.html', {
           'uploaded_file_url2': myfile.name
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


def score_board(request):
    user = request.user
    usernameLength = len(str(request.user.username))
    runtimeList=[]
    m1List = []
    acc_clfList = []
    accList = []
    scores = Score.objects.all().order_by('acc')
    for item in scores:
        name = "upload/"+item.filename
        if name in glob.glob('upload/*'):
             runtimeList.append(item.runtime)
             acc_clfList.append(item.acc_clf)
             accList.append(item.acc)


    userSubmittedTime = []
    userRuntimeScore = []
    userAcc_clfScore = []
    userAccScore = []


    fn = user.tfile1.fn
    fnList = fn.split(" ")
    for item in fnList:
        day = re.findall(r'-(\w+-\w+-\w+):(\w+):',item[usernameLength-1:])
        if len(day[0][1]) <= 1:
            secondPadding = ":0" + day[0][1]
        else:
            secondPadding = ":"+ day[0][1]
        userSubmittedTime.append(day[0][0] + secondPadding)
        try:
            userRuntimeScore.append(Score.objects.get(filename=item).runtime)
            userAcc_clfScore.append(Score.objects.get(filename=item).acc_clf)
            userAccScore.append(Score.objects.get(filename=item).acc)
        except:
            userRuntimeScore.append("Not Provided")
            userAcc_clfScore.append("Not Provided")
            userAccScore.append("Not Provided")

    l = len(runtimeList)
    if l < 5:
        for i in range(0,5-l):
            runtimeList.append("None")
            acc_clfList.append("None")
            accList.append("None")

    RankList = ["1st","2nd","3rd","4th","5th"]
    zipScore = zip(userSubmittedTime, userRuntimeScore,userAcc_clfScore,userAccScore)
    zipRank = zip(RankList, runtimeList,acc_clfList,accList)


    return render(request, 'app/score_board.html',
        {'zipRank': zipRank,
        'zipScore': zipScore,})
