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

# Write directories for file submission destination here
HASHED_TO_ORIGINAL = "hash_to_originalfilename.json"
TRACK1_HASHED_DIR = "submissions_track1/"
TRACK2_HASHED_DIR = "submissions_track2/"
TRACK1_ORIGINAL_DIR = "upload/"
TRACK2_ORIGINAL_DIR = "upload2/"
ROUND2_TRACK1_HTO = "round2/track1_hash_to_originalfilename.json"
ROUND2_TRACK2_HTO = "round2/track2_hash_to_originalfilename.json"
ROUND2_TRACK1_HASHED_CLASSIFICATION = "round2/submissions_track1/classification/"
ROUND2_TRACK1_HASHED_DETECTION = "round2/submissions_track1/detection/"
ROUND2_TRACK1_ORIGINAL_CLASSIFICATION = "round2/track1_original/classification/"
ROUND2_TRACK1_ORIGINAL_DETECTION = "round2/track1_original/detection/"
ROUND2_TRACK2_HASHED_DIR = "round2/submissions_track2/"
ROUND2_TRACK2_ORIGINAL_DIR = "round2/track2_original/"
TRACK1_HTML_FILE_NAME_1 = "track1_classification_file"
TRACK1_HTML_FILE_NAME_2 = "track1_detection_file"
TRACK2_HTML_INPUT_NAME = "myfile2"

# Home page
#def index(request):
#    return render(request, 'app/index.html')

def index2(request):
    return render(request, 'app/index2.html')

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
        if request.method == 'POST':
            if request.FILES[TRACK1_HTML_FILE_NAME_1]:
                classification_file = request.FILES[TRACK1_HTML_FILE_NAME_1]
            try:
                if request.FILES[TRACK1_HTML_FILE_NAME_2]:
                    detection_file = request.FILES[TRACK1_HTML_FILE_NAME_2]

            except:
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug("error getting detection file")

        user_file_name = str(classification_file.name).rsplit('.',1)

        # submission files format restriction
        if user_file_name[1] != "lite" and user_file_name[1] != "tflite":
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Track 1 Submission Failure: File format must be .lite"
        })
 
        if user_file_name[0] != str(request.user.username):
            return render(request, 'app/simple_upload.html', {
            'wrong_file': "Track 1 Submission Failure: File name must be the log-in name"
        })

        # getting date and time for records
        tz = pytz.timezone('America/New_York')
        now = datetime.datetime.now(tz)
        name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(user_file_name[0], now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)

        submissionCounts = 0

    #     for i in glob.glob('upload/*'):
    #          l = len(str(request.user.username))
    #          nm = re.search(r'^(\w+)-2018-', i[7:])
    #          nm = nm.group()
    #          if nm[:-6] == str(request.user.username):
    #              day = re.findall(r'-(\w+-\w+)-\w+:',i[l-1:])
    #              day_now = "{0}-{1}".format(now.month,now.day)
    #              if (day != []):
    #                 #return render(request, 'app/simple_upload.html', {
    #         #'wrong_file': "{} {}".format(day[0],day_now)})
    #                 if (day[0] == day_now):
    #                     submissionCounts += 1
    #
    #     if submissionCounts > 3:
    #        return render(request, 'app/simple_upload.html', {
    # 'wrong_file': "Track 1 Submission Failure: Three submissions per day"})
        true_filename = name+".lite"
        model_validation_dir = '/home/bofu/lpirc/main_dir/initial_dir/LPIRC_2018_Track1_Submission/model_validation/'
        tensorflow_dir = '/home/bofu/tensorflow'
        try:
            with open('round2/model_validation/'+name+".lite", 'wb+') as destination:
                for chunk in classification_file.chunks():
                    destination.write(chunk)

            # Model validation

            orig_dir = os.getcwd()
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('This is the output : ' + str(orig_dir))

            os.chdir(tensorflow_dir)
            retval = os.getcwd()
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('This is the output : ' + str(retval))

            retval = os.system('ls')
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('This is the output : ' + str(retval))

            os.system('touch WORKSPACE')
            test_output = os.popen('bazel-bin/tensorflow/contrib/lite/java/ovic/ovic_validator '+ model_validation_dir + true_filename).read()
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('This is the test result : ' + str(test_output))

            output_split = test_output.split()
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('This is the test result : ' + output_split[0])
            os.chdir(orig_dir)
            if 'Successfully' in test_output:
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug('test passed')
            elif 'Failed' in test_output:
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug('test failed')
                return render(request, 'app/simple_upload.html', {
                    'invalid_model': classification_file.name #" did not pass the bazel test"
                })
            else:
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug('unknown error')
                return render(request, 'app/simple_upload.html', {
                    'error_message': 'Error in process of validation'
                })
        except:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('unknown error1')

        final_dir = os.getcwd()

        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('final_dir = ' + final_dir)

        try:
            os.remove(model_validation_dir+true_filename)
        except OSError as e:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('Failed with: ' + e.strerror)
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('Error code: ' + e.code)

        # ORIGINAL FILE UPLOAD
        # file upload process by chunks to save system's memory
        # save classification with original name
        with open(ROUND2_TRACK1_ORIGINAL_CLASSIFICATION + name +".lite", 'wb+') as destination:
            for chunk in classification_file.chunks():
                destination.write(chunk)

        with open(ROUND2_TRACK1_ORIGINAL_DETECTION + name +".lite", 'wb+') as destination:
            for chunk in detection_file.chunks():
                destination.write(chunk)

        # hash file name
        hash_of_filename = hashfunction(name.encode('utf-8')).hexdigest()
        hash_of_filename = hash_of_filename + ".lite"
        nameStore = name + ".lite"

        try:
            with open(ROUND2_TRACK1_HTO, "r") as jsonFile:
                jsonFile.close()

        except Exception as exc:

            with open(ROUND2_TRACK1_HTO, "w") as jsonFile:
                json.dump({}, jsonFile, indent=2)
                jsonFile.close()

        with open(ROUND2_TRACK1_HTO, "r+") as jsonFile:
            data = json.load(jsonFile)
            data[hash_of_filename] = nameStore
            jsonFile.seek(0)
            json.dump(data, jsonFile, indent=2)
            jsonFile.truncate()


        # file upload process by chunks to save system's memory
        with open(ROUND2_TRACK1_HASHED_CLASSIFICATION + hash_of_filename, 'wb+') as destination:
            for chunk in classification_file.chunks():
                destination.write(chunk)

        with open(ROUND2_TRACK1_HASHED_DETECTION + hash_of_filename, 'wb+') as destination:
            for chunk in detection_file.chunks():
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
            'uploaded_file_url': classification_file.name + " and " + detection_file.name + " has been successfully submitted"
        })

    except:
        try:
            if request.method == 'POST' and request.FILES[TRACK2_HTML_INPUT_NAME]:
                myfile = request.FILES[TRACK2_HTML_INPUT_NAME]

            user_file_name = str(myfile.name).rsplit('.',1)
            # if myfile.name[-5:] != ".lite":
            #     return render(request, 'app/simple_upload.html', {
            #
            #    'wrong_file2': "Track 2 Submission Failure: File format must be .lite"
            #
            # })
            # if str(myfile.name[:-5]) != str(request.user.username):
            if user_file_name[0] != str(request.user.username):
                return render(request, 'app/simple_upload.html', {
                'wrong_file2': "Track 2 Submission Failure: File name must be the log-in name!"
            })

            tz = pytz.timezone('America/New_York')
            now = datetime.datetime.now(tz)
            name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(user_file_name[0], now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)

            # for i in glob.glob('upload2/*'):
            #     l = len(str(request.user.username))
            #     nm = re.search(r'^(\w+)-2018-', i[8:])
            #     nm = nm.group()
            #     if nm[:-6] == str(request.user.username):
            #         day = re.findall(r'-(\w+-\w+)-\w+:',i[l-1:])
            #         day_now = "{0}-{1}".format(now.month,now.day)
            #         if (day != []):
            #         #return render(request, 'app/simple_upload.html', {
            # #'wrong_file': "{} {}".format(day[0],day_now)})
            #
            #
            #              if (day[0] == day_now):
            #                    return render(request, 'app/simple_upload.html', {
            #                    'wrong_file2': "Submission Failure: One submission per day"})



            # file upload process by chunks to save system's memory
            with open(ROUND2_TRACK2_ORIGINAL_DIR + name +"." + user_file_name[1], 'wb+') as destination:
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
            hash_of_filename = hash_of_filename + "." + user_file_name[1]
            nameStore = name + "." + user_file_name[1]

            try:
                with open(ROUND2_TRACK2_HTO, "r") as jsonFile:
                    jsonFile.close()

            except Exception as exc:

                with open(ROUND2_TRACK2_HTO, "w") as jsonFile:
                    json.dump({}, jsonFile, indent=2)
                    jsonFile.close()

            with open(ROUND2_TRACK2_HTO, "r+") as jsonFile:
                data = json.load(jsonFile)
                data[hash_of_filename] = nameStore
                jsonFile.seek(0)
                json.dump(data, jsonFile, indent=2)
                jsonFile.truncate()


            # file upload process by chunks to save system's memory
            with open(ROUND2_TRACK2_HASHED_DIR + hash_of_filename, 'wb+') as destination:
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
           'uploaded_file_url2': myfile.name + " has been successfully submitted"
            })
        except:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('unknown error2')
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
    filenameList=[]
    runtimeList=[]
    m1List = []
    acc_clfList = []
    accList = []
    n_clfList = []
    acc_over_timeList = []
    # feedback_message = []
    scores = Score.objects.all().order_by('-acc', 'runtime')
    for item in scores:
        name = "upload/"+item.filename
        if name in glob.glob('upload/*'):
             filenameList.append(item.filename)
             runtimeList.append(item.runtime)
             acc_clfList.append(item.acc_clf)
             accList.append(item.acc)
             n_clfList.append(item.n_clf)
             acc_over_timeList.append(item.acc_over_time)


    userSubmittedTime = []
    userRuntimeScore = []
    userAcc_clfScore = []
    userAccScore = []
    userN_clfScore = []
    userAcc_over_timeScore = []
    userFeedback_message = []

    try:
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
                userN_clfScore.append(Score.objects.get(filename=item).n_clf)
                userAcc_over_timeScore.append(Score.objects.get(filename=item).acc_over_time)
                userFeedback_message.append(Score.objects.get(filename=item).message)
            except:
                userRuntimeScore.append("Not Provided")
                userAcc_clfScore.append("Not Provided")
                userAccScore.append("Not Provided")
                userN_clfScore.append("Not Provided")
                userAcc_over_timeScore.append("Not Provided")
                userFeedback_message.append("Not Provided")
    except:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('user has not submitted a file')

    l = len(runtimeList)
    if l < 5:
        for i in range(0,5-l):
            runtimeList.append("None")
            acc_clfList.append("None")
            accList.append("None")
            n_clfList.append("None")
            acc_over_timeList.append("None")

    RankList = ["1st","2nd","3rd","4th","5th","6th","7th","8th","9th","10th","11th","12th","13th","14th","15th","16th","17th","18th","19th","20th"]
    zipScore = zip(userSubmittedTime, userRuntimeScore,userAcc_clfScore,userAccScore, userN_clfScore, userAcc_over_timeScore, userFeedback_message)
    zipRank = zip(filenameList, RankList, runtimeList,acc_clfList,accList, n_clfList, acc_over_timeList)

    # Score.objects.all().delete() #to clear score objects
    return render(request, 'app/score_board.html',
        {'zipRank': zipRank,
        'zipScore': zipScore,})

def score_board_admin(request):
    user = request.user
    usernameLength = len(str(request.user.username))
    filenameList=[]
    runtimeList=[]
    m1List = []
    acc_clfList = []
    accList = []
    n_clfList = []
    acc_over_timeList = []
    # feedback_message = []
    scores = Score.objects.all().order_by('-acc', 'runtime')
    for item in scores:
        name = "upload/"+item.filename
        if name in glob.glob('upload/*'):
             filenameList.append(item.filename)
             runtimeList.append(item.runtime)
             acc_clfList.append(item.acc_clf)
             accList.append(item.acc)
             n_clfList.append(item.n_clf)
             acc_over_timeList.append(item.acc_over_time)


    userSubmittedTime = []
    userRuntimeScore = []
    userAcc_clfScore = []
    userAccScore = []
    userN_clfScore = []
    userAcc_over_timeScore = []
    userFeedback_message = []

    try:
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
                userN_clfScore.append(Score.objects.get(filename=item).n_clf)
                userAcc_over_timeScore.append(Score.objects.get(filename=item).acc_over_time)
                userFeedback_message.append(Score.objects.get(filename=item).message)
            except:
                userRuntimeScore.append("Not Provided")
                userAcc_clfScore.append("Not Provided")
                userAccScore.append("Not Provided")
                userN_clfScore.append("Not Provided")
                userAcc_over_timeScore.append("Not Provided")
                userFeedback_message.append("Not Provided")
    except:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('user has not submitted a file')

    l = len(runtimeList)
    if l < 5:
        for i in range(0,5-l):
            runtimeList.append("None")
            acc_clfList.append("None")
            accList.append("None")
            n_clfList.append("None")
            acc_over_timeList.append("None")

    # RankList = ["1st","2nd","3rd","4th","5th","6th","7th","8th","9th","10th","11th","12th","13th","14th","15th","16th","17th","18th","19th","20th"]
    RankList = list(range(1, 135))
    zipScore = zip(userSubmittedTime, userRuntimeScore,userAcc_clfScore,userAccScore, userN_clfScore, userAcc_over_timeScore, userFeedback_message)
    zipRank = zip(filenameList, RankList, runtimeList,acc_clfList,accList, n_clfList, acc_over_timeList)

    # Score.objects.all().delete() #to clear score objects
    return render(request, 'app/score_board_admin.html',
        {'zipRank': zipRank,
        'zipScore': zipScore,})
