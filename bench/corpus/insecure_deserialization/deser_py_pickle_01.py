"""Practice sample: pickle of a session cookie."""
import pickle
from flask import request

def restore_session():
    blob = request.cookies.get('session')
    state = pickle.loads(blob.encode('latin1'))
    return state
