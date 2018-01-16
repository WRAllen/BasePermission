from app.auth.models import Role,Url,User
from flask_login import  current_user
from .. import db
from functools import wraps
from flask import render_template
from .tips import PER

def permissionControl(url_func):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            array=[]
            user=User.query.filter_by(id=current_user.id).first()
            for role in user.roles:
                for url in role.urls:
                    array.append(url.url_func)
            if url_func not in array:
                return PER['url_func']
            return f(*args, **kwargs)
        return decorated_function
    return decorator