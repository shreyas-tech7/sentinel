"""Practice sample: shell=True with a formatted command."""
import subprocess
from flask import request

def dns_lookup():
    host = request.form['host']
    result = subprocess.run(f"nslookup {host}", shell=True, capture_output=True)
    return result.stdout
