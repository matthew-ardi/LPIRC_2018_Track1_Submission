from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required

# Create your views here.

from django.http import HttpResponse
import mimetypes
import os
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def send_zip(request):


    if request.method == 'GET':
        if request.user.username == "THE_ONE_ALLOWED_USER":
            shutil.make_archive("files", 'zip', BASE_DIR + "/media/")
            file_path = BASE_DIR + "/files.zip"
            filename = "files.zip"
            # Grab ZIP file from in-memory, make response with correct MIME-type
            response = HttpResponse(open(file_path, 'rb').read(),\
                                                             content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename=filename'
            return response

        # otherwise ask for authentification
        response = HttpResponse("")
        response.status_code = 401
        response['WWW-Authenticate'] = 'Basic realm="restricted area"'
        return response

