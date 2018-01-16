from flask import Blueprint

initdb = Blueprint('initdb', __name__)

from .views import *