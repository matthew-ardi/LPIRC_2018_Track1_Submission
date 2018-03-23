import os
import mimetypes
import shutil
import json

from os import listdir
from os.path import isfile, join

from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
            #compress the upload_files files directory and save this compressed file as files.zip in the root directory
            shutil.make_archive("files", 'zip', BASE_DIR + "/media/")

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
def list_files(request):
    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':

            submission_folder = BASE_DIR + "/media/"
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
def get_file(request, requested_file):

    # checking for basic http_auth
    if 'HTTP_AUTHORIZATION' in request.META:
        [user, password] = request.META['HTTP_AUTHORIZATION'].split(" ")

        if user == os.environ['ALLOWED_USER'] and password == os.environ['ALLOWED_USER_PASSWORD'] \
        and request.method == 'GET':
            try:
                #grab requested file from in-memory, make response with correct MIME-type
                returnFile = BASE_DIR+"/media/"+requested_file
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