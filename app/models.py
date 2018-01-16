from . import db

class BaseTable(db.Model): 
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(64),unique=True)

