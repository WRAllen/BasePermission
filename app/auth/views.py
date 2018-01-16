# -*- coding:utf-8 -*-
from flask import render_template, redirect, request, url_for, flash,make_response,session
from flask_login import login_user, logout_user, login_required 
from flask_login import current_user
from app.auth.models import User,Role,Url,Menu,Perm
from . import auth
from app.auth.permissioncontrol import permissionControl
from .forms import LoginForm,RegistrationForm
from .. import db
import json
from .tips import VIE


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(num=form.num.data).first() 
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            resp = make_response(redirect(request.args.get('next') or url_for('main.index')))
        
            return resp

        flash(VIE['login_auth'])

    return render_template('auth/login.html', form=form)


@auth.route('/logout') 
@login_required 
def logout():
    logout_user()

    flash('你已经退出登录！')

    return redirect(url_for('auth.login'))

###用户注册
@auth.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit() and form.validate():
        user = User(num=form.num.data,username=form.username.data,password=form.password.data)

        user.imgurl='/static/upload/img/1.jpg'
        ###给角色默认的头像
        db.session.add(user)
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html',form=form)



@auth.before_app_request
def before_request():
    '''
        如果返回响应或重定向，会直接发送至客户端，不会调用请求视图函数
    '''
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.'\
            and request.endpoint != 'static':

        return redirect(url_for('auth.unconfirmed'))




@auth.route('/unconfirmed')
def unconfirmed():
    '''
        尚未确认的账户需要激活
    '''
    if current_user.confirmed:
        return redirect(url_for('main.index'))

    return render_template('auth/unconfirmed.html')



@auth.route("/usermanage")
@permissionControl('auth.userManage')
@login_required 
def userManage():
    '''
        管理用户和角色
    '''
    alluser=User.query.order_by(User.id).all()
    allrole=Role.query.order_by(Role.id).all()
    allperm=Perm.query.order_by(Perm.id).all()

    return render_template('auth/usermanage.html',alluser=alluser,allrole=allrole,allperm=allperm)



@auth.route("/urlmanage")
@permissionControl('auth.urlManage')
@login_required
def urlManage():
    '''
        管理路由和菜单
    '''
    allurl=Url.query.order_by(Url.id).all()
    allmenu=Menu.query.order_by(Menu.id).all()
    return render_template('auth/urlmanage.html',allurl=allurl,allmenu=allmenu)



@auth.route("/rolemanage")
@permissionControl('auth.roleManage')
@login_required 
def roleManage():
    '''
        管理角色和路由
    '''
    allurl=[]

    allrole=Role.query.order_by(Role.id).all()
    allmenu=Menu.query.order_by(Menu.id).all()

    result2=Url.query.order_by(Url.id).all()
    for x2 in result2:
        if x2.menus:
            allurl.append([x2,x2.menus[0]])
        else:
            allurl.append([x2,''])
        

    return render_template('auth/permission.html',allrole=allrole,allurl=allurl,allmenu=allmenu)



@auth.route('/updaterolesource',methods=["POST"])
@login_required
def updateRoleSource():
    rolename=request.form.getlist('role_id')
    arr_urlid=request.form.getlist('now_url[]')
    str_split = rolename[0].split('_')[-1]
    roleid=int(str_split)
    role=Role.query.filter_by(id=roleid).first()
    role.urls=[]
    url = Url.query.filter(Url.id.in_(arr_urlid)).all()
    role.urls=url
    db.session.add(role)
    return "修改成功"



@auth.route('/updatesource')
@login_required
def update():
    '''
        ajax的访问地址,用于角色管理界面
    '''
    rolename=request.args.get('role_name')
    result=Role.query.filter_by(name=rolename).first()
    roleid=result.id
    role=Role.query.filter_by(id=roleid).first()
    dicta={}
    array=[]
    for x in role.urls:
        array.append(x.id)
    dicta['array']=array
    return json.dumps(dicta)



@auth.route('/updateuserinfo',methods=["POST"])
@login_required
def updateUserInfo():
    '''
        ajax的访问地址,用于修改信息
    '''
    userid=request.form.getlist('userid')
    arr_per=request.form.getlist('arr_per[]')
    activate=request.form.getlist('activate')
    rol_id=request.form.getlist('rol_id[]')
    user=User.query.filter_by(id=userid).first()
    ###查询出选择的用户
    perm=Perm.query.filter(Perm.id.in_(arr_per)).order_by(Perm.id).all()
    ###查询出选择的权限
    user.perms=perm
    confirmed=int(activate[0])
    ###把str转化为int
    user.confirmed=confirmed
    role=Role.query.filter(Role.id.in_(rol_id)).order_by(Role.id).all()
    user.roles=role
    db.session.add(user)

    return "success"



@auth.route('/updateurlmenu')
@login_required
def updateUrlMenu():
	'''
		ajax的访问地址,用于保存url与menu的关系
	'''
	now_url_menu=request.args.get('now_url_menu')
	now_url_name=request.args.get('now_url_name')
	url_id=request.args.get('url_id')
	url=Url.query.filter_by(id=url_id).first()
	menu=Menu.query.filter_by(name=now_url_menu).first()

	url.name=now_url_name
	url.menus=[menu]
	db.session.add(url)

	return "ad"
    