"""Practice sample: open() on a request-supplied relative path."""
from flask import request

def serve_note():
    note = request.args.get('note')
    with open(f'static/notes/{note}', 'rb') as fh:
        return fh.read()
