"""Practice sample: user value rendered through Markup (no autoescape)."""
from flask import Markup, request

def profile_badge():
    nickname = request.args.get('nickname', '')
    return Markup(f"<span class='badge'>{nickname}</span>")
