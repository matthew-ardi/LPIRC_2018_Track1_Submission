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
from api.models import Score, Score_r2, Score_r2_detection
from app.models import Tfile1, Tfile1_r2
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
ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION = "round2/invalid_model/classification/"
ROUND2_TRACK1_INVALID_MODEL_DETECTION = "round2/invalid_model/detection/"
ROUND2_TRACK2_HASHED_DIR = "round2/submissions_track2/"
ROUND2_TRACK2_ORIGINAL_DIR = "round2/track2_original/"

# HTML names - identifier
TRACK1_HTML_FILE_NAME_1 = "track1_classification_file"
TRACK1_HTML_FILE_NAME_2 = "track1_detection_file"
TRACK2_HTML_INPUT_NAME = "myfile2"

# Home page
#def index(request):
#    return render(request, 'app/index.html')
def makedirs(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == 17:
            # Dir already exists. No biggie.
            pass

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
                    'uid': urlsafe_base64_encode(force_bytes(model1.pk)).decode(),
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
            classification_file_exist = False
            detection_file_exist = False
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('post detected ')
            try:
                if request.FILES[TRACK1_HTML_FILE_NAME_1]:
                    classification_file = request.FILES[TRACK1_HTML_FILE_NAME_1]
                    classification_file_exist = True
            except:
                pass

            try:
                if request.FILES[TRACK1_HTML_FILE_NAME_2]:
                    detection_file = request.FILES[TRACK1_HTML_FILE_NAME_2]
                    detection_file_exist = True
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('detection only ')

            except:
                pass

            if classification_file_exist != True and detection_file_exist != True:
                raise Exception()

            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.debug('request files done ')
            if classification_file_exist is not True and detection_file_exist is not True:
                return render(request, 'app/simple_upload.html', {
                        'wrong_file': "Track 1 Submission Failure: no files detected"
                    })

            if classification_file_exist is True:
                user_file_name = str(classification_file.name).rpartition('.')

                # submission files format restriction
                if "lite" not in user_file_name and "tflite" not in user_file_name:
                    return render(request, 'app/simple_upload.html', {
                    'wrong_file': "Track 1 Submission Failure: File format must be .lite or .tflite"
                })
            
            if detection_file_exist is True:
                user_detect_name = str(detection_file.name).rpartition('.')

                # submission files format restriction
                if "lite" not in user_detect_name and "tflite" not in user_detect_name:
                    return render(request, 'app/simple_upload.html', {
                    'wrong_file': "Track 1 Submission Failure: File format must be .lite or .tflite"
                })

            # getting date and time for records
            tz = pytz.timezone('America/New_York')
            now = datetime.datetime.now(tz)
            name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(str(request.user.username), now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)

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
            model_validation_dir = ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION
            tensorflow_dir = '/home/bofu/tensorflow'
            try:
                if classification_file_exist is True:
                    makedirs(ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION)
                    with open(ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION+name+".lite", 'wb+') as destination:
                        for chunk in classification_file.chunks():
                            destination.write(chunk)
                
                if detection_file_exist is True:
                    makedirs(ROUND2_TRACK1_INVALID_MODEL_DETECTION)
                    with open(ROUND2_TRACK1_INVALID_MODEL_DETECTION+name+".lite", 'wb+') as destination:
                        for chunk in detection_file.chunks():
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
                if classification_file_exist is True:
                    test_output_classification = os.popen('bazel-bin/tensorflow/lite/java/ovic/ovic_validator '+ orig_dir + '/' + ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION + true_filename + " classify").read()
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('This is the classification test result : ' + str(test_output_classification))
                else:
                    test_output_classification = "None"

                if detection_file_exist is True:
                    test_output_detection = os.popen('bazel-bin/tensorflow/lite/java/ovic/ovic_validator '+ orig_dir + '/' + ROUND2_TRACK1_INVALID_MODEL_DETECTION + true_filename + " detect").read()
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('This is the detection test result : ' + str(test_output_detection))
                else:
                    test_output_detection = "None"

                output_split = test_output_classification.split()
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug('This is the test result : ' + output_split[0])
                os.chdir(orig_dir)
                
                if classification_file_exist is True and 'Successfully' in test_output_classification:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('test passed')
                elif 'Failed' in test_output_classification:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('test failed')
                    return render(request, 'app/simple_upload.html', {
                        'invalid_model': classification_file.name #" Classification model did not pass the bazel test"
                    })
                elif classification_file_exist is False:
                    pass
                else:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('unknown error')
                    return render(request, 'app/simple_upload.html', {
                        'error_message': 'Error in process of validation'
                    })

                if detection_file_exist is True and 'Successfully' in test_output_detection:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('test passed')
                elif 'Failed' in test_output_detection:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('test failed')
                    return render(request, 'app/simple_upload.html', {
                        'invalid_model': detection_file.name #" Classification model did not pass the bazel test"
                    })
                elif detection_file_exist is False:
                    pass
                else:
                    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    logging.debug('unknown error')
                    return render(request, 'app/simple_upload.html', {
                        'error_message': 'Error in process of validation'
                    })
            except:
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                logging.debug('unknown error1')

            # final_dir = os.getcwd()

            # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            # logging.debug('final_dir = ' + final_dir)

            # try:
            #     os.remove(ROUND2_TRACK1_INVALID_MODEL_CLASSIFICATION+true_filename)
            #     os.remove(ROUND2_TRACK1_INVALID_MODEL_DETECTION+true_filename)
            # except OSError as e:
            #     logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            #     logging.debug('Failed with: ' + e.strerror)
            #     logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
            #     logging.debug('Error code: ' + e.code)

            # ORIGINAL FILE UPLOAD
            # file upload process by chunks to save system's memory
            # save classification with original name

            if classification_file_exist is True:
                makedirs(ROUND2_TRACK1_ORIGINAL_CLASSIFICATION)
                with open(ROUND2_TRACK1_ORIGINAL_CLASSIFICATION + name +".lite", 'wb+') as destination:
                    for chunk in classification_file.chunks():
                        destination.write(chunk)
            
            if detection_file_exist is True:
                makedirs(ROUND2_TRACK1_ORIGINAL_DETECTION)
                with open(ROUND2_TRACK1_ORIGINAL_DETECTION + name +".lite", 'wb+') as destination:
                    for chunk in detection_file.chunks():
                        destination.write(chunk)

            
            # hash file name - classification model
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
            if classification_file_exist is True:
                makedirs(ROUND2_TRACK1_HASHED_CLASSIFICATION)
                with open(ROUND2_TRACK1_HASHED_CLASSIFICATION + hash_of_filename, 'wb+') as destination:
                    for chunk in classification_file.chunks():
                        destination.write(chunk)

            if detection_file_exist is True:
                makedirs(ROUND2_TRACK1_HASHED_DETECTION)
                with open(ROUND2_TRACK1_HASHED_DETECTION + hash_of_filename, 'wb+') as destination:
                    for chunk in detection_file.chunks():
                        destination.write(chunk)

            if classification_file_exist is True and detection_file_exist is True:
                return render(request, 'app/simple_upload.html', {
                    'uploaded_file_url': "Your classification and detection models have been successfully submitted"
                })
            elif classification_file_exist is True:
                return render(request, 'app/simple_upload.html', {
                    'uploaded_file_url': "your classification model has been successfully submitted"
                })
            elif detection_file_exist is True:
                return render(request, 'app/simple_upload.html', {
                    'uploaded_file_url': "your detection model has been successfully submitted"
                })
            else:
                return render(request, 'app/simple_upload.html', {
                    'wrong_file': "Track 1 Submission Failure[1742]"
            })
        else:
            return render(request, 'app/simple_upload.html')
    except:
        try:
            if request.method == 'POST' and request.FILES[TRACK2_HTML_INPUT_NAME]:
                myfile = request.FILES[TRACK2_HTML_INPUT_NAME]

            user_file_name = str(myfile.name).rpartition('.')
            # if myfile.name[-5:] != ".lite":
            #     return render(request, 'app/simple_upload.html', {
            #
            #    'wrong_file2': "Track 2 Submission Failure: File format must be .lite"
            #
            # })
            # if str(myfile.name[:-5]) != str(request.user.username):

            tz = pytz.timezone('America/New_York')
            now = datetime.datetime.now(tz)
            name = "{0}-{1}-{2}-{3}-{4}:{5}:{6}:{7}".format(str(request.user.username), now.year, now.month, now.day,now.hour,now.minute,now.second,now.microsecond)

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
            makedirs(ROUND2_TRACK2_ORIGINAL_DIR)
            with open(ROUND2_TRACK2_ORIGINAL_DIR + name +".lite", 'wb+') as destination:
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
            makedirs(ROUND2_TRACK2_HASHED_DIR)
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

# Score board for track 1 round 2 (Nov 1 - 15, 2018)
def score_board_r2(request):
    user = request.user
    usernameLength = len(str(request.user.username))

    # Classification Lists - Public Leaderboard
    filenameList=[]
    runtimeList=[]
    m1List = []
    acc_clfList = []
    accList = []
    n_clfList = []
    acc_over_timeList = []
    metricList = []
    ref_accList = []
    bucketList = []
    # feedback_message = []
    scores = Score_r2.objects.all().order_by('-acc', 'runtime')
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.debug('getting scoreboard')
    for item in scores:
        name = ROUND2_TRACK1_ORIGINAL_CLASSIFICATION + item.filename
        if name in glob.glob(ROUND2_TRACK1_ORIGINAL_CLASSIFICATION + '*'):
             filenameList.append(item.filename)
             runtimeList.append(item.runtime)
             acc_clfList.append(item.acc_clf)
             accList.append(item.acc)
             n_clfList.append(item.n_clf)
             acc_over_timeList.append(item.acc_over_time)
             metricList.append(item.metric)
             ref_accList.append(item.ref_acc)
             bucketList.append(item.bucket)

    # Detection Lists - Public Leaderboard
    filenameList_detect = []
    runtimeList_detect = []
    map_over_timeList_detect = []
    map_of_processedList_detect = []

    scores_detection = Score_r2_detection.objects.all()
    for item in scores_detection:
        name = ROUND2_TRACK1_ORIGINAL_DETECTION + item.filename
        if name in glob.glob(ROUND2_TRACK1_ORIGINAL_DETECTION + '*'):
            filenameList_detect.append(item.filename)
            runtimeList_detect.append(item.runtime)
            map_over_timeList_detect.append(item.map_over_time)
            map_of_processedList_detect.append(item.map_of_processed)

    # Classification for Private leaderboard
    userSubmittedTime = []
    userRuntimeScore = []
    userAcc_clfScore = []
    userAccScore = []
    userN_clfScore = []
    userAcc_over_timeScore = []
    userFeedback_message = []
    userMetric = []
    userRef_acc = []
    userBucket = []

    try:
        fn = user.tfile1_r2.fn
        fnList = fn.split(" ")

        for item in fnList:
            day = re.findall(r'-(\w+-\w+-\w+):(\w+):',item[usernameLength-1:])
            if len(day[0][1]) <= 1:
                secondPadding = ":0" + day[0][1]
            else:
                secondPadding = ":"+ day[0][1]
            userSubmittedTime.append(day[0][0] + secondPadding)
            try:
                userRuntimeScore.append(Score_r2.objects.get(filename=item).runtime)
                userAcc_clfScore.append(Score_r2.objects.get(filename=item).acc_clf)
                userAccScore.append(Score_r2.objects.get(filename=item).acc)
                userN_clfScore.append(Score_r2.objects.get(filename=item).n_clf)
                userAcc_over_timeScore.append(Score_r2.objects.get(filename=item).acc_over_time)
                userMetric.append(Score_r2.objects.get(filename=item).metric)
                userRef_acc.append(Score_r2.objects.get(filename=item).ref_acc)
                userBucket.append(Score_r2.objects.get(filename=item).bucket)
                userFeedback_message.append(Score_r2.objects.get(filename=item).message)
            except:
                userRuntimeScore.append("Not Provided")
                userAcc_clfScore.append("Not Provided")
                userAccScore.append("Not Provided")
                userN_clfScore.append("Not Provided")
                userAcc_over_timeScore.append("Not Provided")
                userMetric.append("Not Provided")
                userRef_acc.append("Not Provided")
                userBucket.append("Not Provided")
                userFeedback_message.append("Not Provided")
    except:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('user has not submitted classification file')

    # Detection Private Leaderboard
    userSubmittedTimeDetect = []
    userRuntimeDetectScore = []
    userMapOverTimeDetectScore = []
    userMapOfProcessedDetectScore = []
    userFeedbackDetect_message = []

    try:
        fn = user.tfile1_r2.fn
        fnList = fn.split(" ")

        for item in fnList:
            day = re.findall(r'-(\w+-\w+-\w+):(\w+):',item[usernameLength-1:])
            if len(day[0][1]) <= 1:
                secondPadding = ":0" + day[0][1]
            else:
                secondPadding = ":"+ day[0][1]
            userSubmittedTimeDetect.append(day[0][0] + secondPadding)
            try:
                userRuntimeDetectScore.append(Score_r2_detection.objects.get(filename=item).runtime)
                userMapOverTimeDetectScore.append('{:0.5e}'.format(Score_r2_detection.objects.get(filename=item).map_over_time))
                userMapOfProcessedDetectScore.append(Score_r2_detection.objects.get(filename=item).map_of_processed)
                userFeedbackDetect_message.append(Score_r2_detection.objects.get(filename=item).message)
            except:
                userRuntimeDetectScore.append("Not Provided")
                userMapOverTimeDetectScore.append("Not Provided")
                userMapOfProcessedDetectScore.append("Not Provided")
                userFeedbackDetect_message.append("Not Provided")
    except:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('user has not submitted Detection file')

    # Classification - public leaderboard
    l = len(runtimeList)
    if l < 5:
        for i in range(0,5-l):
            runtimeList.append("None")
            acc_clfList.append("None")
            accList.append("None")
            n_clfList.append("None")
            acc_over_timeList.append("None")
            metricList.append("None")
            ref_accList.append("None")
            bucketList.append("None")

    l = len(runtimeList_detect)
    if l < 5:
        for i in range(0,1-l):
            filenameList_detect.append("Coming Soon")
            runtimeList_detect.append("Coming Soon")
            map_over_timeList_detect.append("Coming Soon")
            map_of_processedList_detect.append("Coming Soon")

    # collect all metadata to be transmitted to front-end
    RankList = ["1st","2nd","3rd","4th","5th","6th","7th","8th","9th","10th","11th","12th","13th","14th","15th","16th","17th","18th","19th","20th"]
    zipScore = zip(
        userSubmittedTime, 
        userRuntimeScore,
        userAcc_clfScore,
        userAccScore, 
        userN_clfScore, 
        userAcc_over_timeScore, 
        userMetric,
        userRef_acc,
        userBucket,
        userFeedback_message
        )
    zipRank = zip(
        filenameList, 
        RankList, 
        runtimeList,
        acc_clfList,
        accList, 
        n_clfList, 
        acc_over_timeList,
        metricList,
        ref_accList,
        bucketList
        )

    zipScore_detect = zip(
        userSubmittedTimeDetect,
        userRuntimeDetectScore,
        userMapOverTimeDetectScore,
        userMapOfProcessedDetectScore,
        userFeedbackDetect_message
    )

    zipRank_detect = zip(
        RankList,
        filenameList_detect,
        runtimeList_detect,
        map_over_timeList_detect,
        map_of_processedList_detect
    )
    # Score.objects.all().delete() #to clear score objects
    return render(request, 'app/score_board_r2.html',
        {'zipRank': zipRank,
        'zipScore': zipScore,
        'zipScore_detect': zipScore_detect,
        'zipRank_detect': zipRank_detect})

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
