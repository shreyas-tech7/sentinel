"""Practice sample: yaml.load without a safe loader."""
import yaml
from flask import request

def load_config_payload():
    return yaml.load(request.data)
