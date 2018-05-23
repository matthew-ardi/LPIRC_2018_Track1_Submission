import os
import mimetypes
import shutil
import json

from api.models import Score
from os import listdir
from os.path import isfile, join
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#BASE_DIR = './'
track1_submissions_folder = "/submissions_track1/"
track2_submissions_folder = "/submissions_track2/"

# function to send compressed directory of submitted files
# a sample GET request:
# curl -H "Authorization: username password" http://lpirc.ecn.purdue.edu/submissions/files/ --output compressed_directory_of_submissions.zip
def send_zip(request):

    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':

            #shutil is a native library
            #compress the submissions_track1 files directory and save this compressed file as files.zip in the root directory
            shutil.make_archive("files", 'zip', BASE_DIR + "/submissions_track1/")

            #grab ZIP file from in-memory, make response with correct MIME-type
            file_path = BASE_DIR + "/files.zip"
            filename = "files.zip"
            response = HttpResponse(open(file_path, 'rb').read(),\
                                                     content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename=filename'
            return response

    #default permission denied 401 response
    response = HttpResponse("")
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="restricted area"'
    return response

# function to send a list of names of submitted files
# a sample GET request:
# curl -H "Authorization: username password" http://lpirc.ecn.purdue.edu/submissions/list_files/ --output compressed_directory_of_submissions.zip
def list_files1(request):
    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':

            submission_folder = BASE_DIR + track1_submissions_folder
            files = [f for f in listdir(submission_folder) if isfile(join(submission_folder, f))]
            response = HttpResponse(json.dumps(files), content_type ="application/json")
            response.status_code = 200
            return response

    #default permission denied 401 response
    response = HttpResponse("")
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="restricted area"'
    return response

def list_files2(request):
    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':

            submission_folder = BASE_DIR + track2_submissions_folder
            files = [f for f in listdir(submission_folder) if isfile(join(submission_folder, f))]
            response = HttpResponse(json.dumps(files), content_type ="application/json")
            response.status_code = 200
            return response

    #default permission denied 401 response
    response = HttpResponse("")
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="restricted area"'
    return response

# function to send a required submitted file
# a sample GET request:
# curl -H "Authorization: username password" http://lpirc.ecn.purdue.edu/submissions/get_file/filename --output submission.tfile
def get_file1(request, requested_file):

    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':
            try:
                #grab requested file from in-memory, make response with correct MIME-type
                returnFile = BASE_DIR + track1_submissions_folder + requested_file
                response = HttpResponse(open(returnFile, 'rb').read(),\
                                                     content_type='application/tfile')
                response['Content-Disposition'] = 'attachment; filename=requested_file'
            except Exception:
                response = HttpResponse("The file does not exist")
                response.status_code = 401
                response['WWW-Authenticate'] = 'Basic realm="restricted area"'
            return response

    #default permission denied 401 response
    response = HttpResponse("")
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="restricted area"'
    return response

def get_file2(request, requested_file):

    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':
            try:
                #grab requested file from in-memory, make response with correct MIME-type
                returnFile = BASE_DIR + track2_submissions_folder + requested_file
                response = HttpResponse(open(returnFile, 'rb').read(),\
                                                     content_type='application/tfile')
                response['Content-Disposition'] = 'attachment; filename=requested_file'
            except Exception:
                response = HttpResponse("The file does not exist")
                response.status_code = 401
                response['WWW-Authenticate'] = 'Basic realm="restricted area"'
            return response

    #default permission denied 401 response
    response = HttpResponse("")
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="restricted area"'
    return response

# function to post scores by JSON format
# a sample POST request:
# curl -X POST -H "Content-Type: application/json" -d '{"filename": "<hash of foo_bar_baz5>.lite","runtime": 123,"metric2": 234,"metric3": 567}' http://127.0.0.1:8000/submissions/postScore/
#@login_required
@csrf_exempt
def postScore(request):
    if request.method == 'POST':
        #user = request.user
        #if request.user.username == 'alanbition':#os.environ['REFEREE']:
            try:
                d=[]
                body_unicode = request.body.decode('utf-8')
                body = json.loads(body_unicode)
                content = body['results']
                for item in content:
                    body = item
                    content = body['filename']
                    orgName = ''.join(content.split())[:-5]
                    with open('hash_to_originalfilename.json','r') as json_data:
                        d = json.load(json_data)
                        orgName = d[content]
                    try:
                        if Score.objects.filter(filename=orgName).exists():
                            obj = Score.objects.get(filename=orgName)
                            obj.runtime = body['runtime']
                            obj.acc_clf = body['acc_clf']
                            obj.acc = body['acc']
                            obj.save()
                        else:
                            p = Score.objects.create(filename=orgName,runtime=body['runtime'],acc_clf=body['acc_clf'],acc=body['acc'])
                            p.save()
                    except Exception as exc:
                        return HttpResponse(exc)


                response = HttpResponse('Post Successful')
                response.status_code = 200
                return response
            except Exception as exc:
                return HttpResponse(exc)

    response = HttpResponse('Post Unsuccessful')
    response.status_code = 401
    return render(request, 'api/action_fail.html')

# function to get scores by filename
# a sample GET request:
# curl http://127.0.0.1:8000/submissions/getScore/foo_bar_baz.lite
#@login_required
@csrf_exempt
def getScore(request, requested_file):
    
    if request.method == 'GET':
        try:
            score = Score.objects.get(filename=requested_file)
        except Exception as exc:
            return HttpResponse(exc)
        response = HttpResponse(score.runtime)
        response.status_code = 200
        return response

    return render(request, 'api/action_fail.html')

@login_required
def listFiles1(request):
    # checking for username
    user = request.user
    if user.username == os.environ['REFEREE']:
        submission_folder = BASE_DIR + track1_submissions_folder
        files = [f for f in listdir(submission_folder) if isfile(join(submission_folder, f))]
        response = HttpResponse(json.dumps(files), content_type ="application/json")
        response.status_code = 200
        return response

    return render(request, 'api/action_fail.html')

@login_required
def listFiles2(request):
    # checking for username
    user = request.user
    if user.username == 'jingchi':
        submission_folder = BASE_DIR + track2_submissions_folder
        files = [f for f in listdir(submission_folder) if isfile(join(submission_folder, f))]
        response = HttpResponse(json.dumps(files), content_type ="application/json")
        response.status_code = 200
        return response

    return render(request, 'api/action_fail.html')

@login_required
def getFile1(request, requested_file):

    # checking for username
    user = request.user
    if user.username == os.environ['REFEREE']:
        try:
            #grab requested file from in-memory, make response with correct MIME-type
            returnFile = BASE_DIR + track1_submissions_folder + requested_file
            response = HttpResponse(open(returnFile, 'rb').read(),\
                                                 content_type='application/tfile')
            response['Content-Disposition'] = 'attachment; filename=requested_file'
        except Exception:
            response = HttpResponse("The file does not exist")
            response.status_code = 401
            response['WWW-Authenticate'] = 'Basic realm="restricted area"'
        return response

    return render(request, 'api/action_fail.html')

@login_required
def getFile2(request, requested_file):

    # checking for username
    user = request.user
    if user.username == 'jingchi':
        try:
            #grab requested file from in-memory, make response with correct MIME-type
            returnFile = BASE_DIR + track2_submissions_folder + requested_file
            response = HttpResponse(open(returnFile, 'rb').read(),\
                                                 content_type='application/tfile')
            response['Content-Disposition'] = 'attachment; filename=requested_file'
        except Exception:
            response = HttpResponse("The file does not exist")
            response.status_code = 401
            response['WWW-Authenticate'] = 'Basic realm="restricted area"'
        return response

    return render(request, 'api/action_fail.html')

