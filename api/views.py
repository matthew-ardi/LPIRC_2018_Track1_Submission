import os
import mimetypes
import shutil

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
            shutil.make_archive("files", 'zip', BASE_DIR + "/upload_files/")

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