from . import initdb
from app import db
from app.auth.models import *
from flask import render_template
import os,csv


@initdb.route("/initdb")
def initDB():

    for x in getDIR('url'):
        url = Url(id = x[0], name = x[1], url_func = x[2])
        checkModel(url,Url,x[0])

    for x2 in getDIR('menu'):
        menu = Menu(id = x2[0],name = x2[1])
        checkModel(menu,Menu,x2[0])

    for x3 in getDIR('perm'):
        perm = Perm(id = x3[0],name = x3[1])
        checkModel(perm,Perm,x3[0])

    for x4 in getDIR('role'):
        role = Role(id = x4[0],name = x4[1])
        checkModel(role,Role,x4[0])

    ROLE = Role.query.filter_by(id = '1').first()
    URLS = Url.query.all()
    ROLE.urls = URLS

    check = User.query.filter_by(num = '9999').first()
    if check == None:
        user = User(num='9999',username='admin',password='123')
        db.session.add(user)


    user.roles = [ROLE]
    user.confirmed = True
    perm = Perm.query.all()
    user.perms = perm

    ini_menu = Menu.query.filter_by(name = '未分类').first()
    for x5 in URLS:
        x5.menus = [ini_menu]

    return render_template('initdb/initdb.html')

def getDIR(name):
    directory=os.getcwd()
    directory = directory+'/app/initdb/csv/'+name+'.csv'
    return csv.reader(open(directory,'r'))

def checkModel(model,Model,model_id):
    checkmodel = Model.query.filter_by(id = model_id).first()
    if checkmodel==None:
        db.session.add(model)

