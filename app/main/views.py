from . import main
from flask_login import login_required 
from flask import render_template, request,session
from app import db
from flask import redirect, url_for
from app.auth.permissioncontrol import permissionControl

@main.route('/')
@login_required
def index():
    return render_template('main/index.html')


@main.route('/order_report')
@permissionControl('main.orderReport')
def orderReport():
    return render_template('main/orderReport.html')



@main.route('/product_report')
@permissionControl('main.productReport')
def productReport():
    return render_template('main/productReport.html')