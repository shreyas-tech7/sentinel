"""Practice sample: requests.get on a form-supplied URL."""
import requests
from flask import request

def import_avatar():
    image_url = request.form['image_url']
    resp = requests.get(image_url, timeout=5)
    return resp.content
