"""Clean sample: safe yaml loader, allowlisted outbound request, contained path."""
import os
import requests
import yaml
from flask import request, send_from_directory

def load_config_payload():
    return yaml.safe_load(request.data)

ALLOWED_HOSTS = ['images.example.internal']

def import_avatar():
    image_url = request.form['image_url']
    host = image_url.split('/')[2]
    if host not in ALLOWED_HOSTS:
        raise ValueError('blocked')
    return requests.get(image_url, timeout=5).content

def serve_note():
    return send_from_directory('static/notes', request.args.get('note'))
