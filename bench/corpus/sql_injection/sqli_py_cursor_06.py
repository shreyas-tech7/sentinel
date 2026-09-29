"""Practice sample: f-string SQL executed directly."""
from flask import request

def get_account(cursor):
    account_id = request.args.get('id')
    query = f"SELECT balance FROM accounts WHERE holder = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchall()
