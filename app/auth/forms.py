# -*- coding:utf-8 -*-
from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email,Regexp,EqualTo
from wtforms import ValidationError
from app.auth.models import User


#表单login
class LoginForm(Form):
	'''
		1 登录表单。StringField构造函数中的可选参数validators指定一个有验证函数组成的列表，在接受用户提交的数据之前验证数据。
		2 电子邮件字段用到了WTForms提供的Length（）和Email（）验证函数。
		3 PasswordField类表示属性为type="password"的<input>元素。
		4 BooleanField类表示复选框。
	'''
	num = StringField('工号', validators=[Required(), Length(4, 4, message="工号位4位数字")],render_kw={"placeholder":"请输入工号"})    
    
	password = PasswordField('密码', validators=[Required()],render_kw={"placeholder":"请输入密码"}) 
    
	remember_me = BooleanField('记住密码')

	submit = SubmitField('登录')

#表单注册Registration
class RegistrationForm(Form):
	'''
		1 注册表单
		2 填写表单时的格式限制(输入邮箱、输入用户名、输入密码、确认密码、注册按钮)
		3 验证账号是否被注册过
		4 验证用户名是否被注册过
	'''
	
	###render_kw={}里面保存默认的提示
	num = StringField('工号', validators=[Required(), Length(4, 4, message="工号位4位数字")],render_kw={"placeholder":"请输入工号"})
	
	username = StringField('用户名',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',\
		0,'用户名必须是字母开头,字母数字结合')],render_kw={"placeholder":"请输入用户名"})
	
	password = PasswordField('密码',validators=[Required(),EqualTo('password2',message='两次密码必须一致')],render_kw={"placeholder":"请输入密码"})
	
	password2 = PasswordField('确认密码',validators=[Required()],render_kw={"placeholder":"请确认密码"})
	
	submit = SubmitField('注册')

	def validate_num(self,field):
		if User.query.filter_by(num=field.data).first():

			raise ValidationError('工号已存在')
	
	
	def validate_username(self,field):

		if User.query.filter_by(username=field.data).first():

			raise ValidationError('用户名已存在.')