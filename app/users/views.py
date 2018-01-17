# -*- coding:utf-8 -*-
from flask import render_template, redirect, request, url_for, flash,make_response,session
from flask_login import login_user, logout_user, login_required 
from flask_login import current_user
from app.auth.models import User,Role,Url,Menu,Perm
from . import users
from app.auth.permissioncontrol import permissionControl
from werkzeug.security import generate_password_hash, check_password_hash
from .. import db
import json,os,time


@users.route('/information')
@login_required
def showInformation():
    userinfo= User.query.filter_by(id=current_user.id).first()
   
    return render_template('users/information.html',userinfo=userinfo)


@users.route('/updatainfo')
@login_required
def updatainfo():
    '''
        ajax保存用户的修改信息
    '''
    name=request.args.get('nickname')
    sex=request.args.get('radios_check')
    email=request.args.get('email_add')
    phone=request.args.get('phone_num')
    birthday=request.args.get('birthday')
    user = User.query.filter_by(id=current_user.id).first()
    user.name=name
    if sex!=None:
        user.sex=int(sex)
    user.email=email
    user.tel=phone
    if birthday==None or birthday=='':
        user.birthday='1970-1-1'
    else:
        user.birthday=birthday
    db.session.add(user)

    return '更新成功'


@users.route('/updatapaw')
@login_required
def updatapaw():
    old_paw=request.args.get('old_paw')
    new_paw=request.args.get('new_paw')
    confirm_paw=request.args.get('confirm_paw')
    user = User.query.filter_by(id=current_user.id).first()
    if user.verify_password(old_paw):
        user.password_hash=generate_password_hash(new_paw)
        db.session.add(user)

        return 'success'

    return '原密码有误'


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@users.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    time_s=int(time.time())
    if request.method == 'POST':
        file = request.files['file']

        if file and allowed_file(file.filename):
            derec_path = os.getcwd()
            upload_path = derec_path+'/app/static/upload/img'
            uploadname = (('%s'+file.filename)%time_s)
            file.save(os.path.join(upload_path, uploadname))
            user = User.query.filter_by(id=current_user.id).first()
            show_path = '/static/upload/img'
            user.imgurl = os.path.join(show_path, uploadname)
            db.session.add(user)
            
    return '上传成功'

