"""Clean sample: parameterized query, quoted command, json parse, env secret."""
import json, os, shlex, subprocess
from flask import request

def lookup(cursor):
    account_id = request.args.get('id')
    cursor.execute('SELECT balance FROM accounts WHERE holder = ?', (account_id,))
    return cursor.fetchall()

def dns_lookup():
    host = request.form['host']
    result = subprocess.run(['nslookup', shlex.quote(host)], capture_output=True)
    return result.stdout

def import_state():
    return json.loads(request.data)

SESSION_KEY = os.environ['SESSION_SECRET']
