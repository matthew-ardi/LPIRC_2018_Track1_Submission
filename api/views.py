from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse
import mimetypes
import os
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def send_zip(request):
    """
    List all code snippets, or create a new snippet.
    """
    if request.method == 'GET':
        shutil.make_archive("files", 'zip', BASE_DIR + "/media/")
        file_path = BASE_DIR + "/files.zip"
        filename = "files.zip"
        # Grab ZIP file from in-memory, make response with correct MIME-type
        response = HttpResponse(open(file_path, 'rb').read(),\
                                                         content_type='application/zip')
        response['Content-Disposition'] = 'attachment; filename=filename'
        return response
