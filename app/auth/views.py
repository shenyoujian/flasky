#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:32
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :auth蓝本中的路由和视图函数

from flask import render_template, redirect, request, url_for, flash
from . import auth                                                          # 1、引入蓝本
from flask_login import login_required, current_user
from flask_login import login_user, logout_user
from ..models import User
from .forms import LoginForm, RegistrationForm
from app import db
from ..email import send_email


# 2、使用蓝本的route修饰器定义与认证相关的路由
@auth.route('/login', methods=['GET', 'POST'])                               # 3、登录用户
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/secret')                                                      # 4、保护路由
@login_required
def secret():
    return 'Only authenticated users are allowed!'


@auth.route('/logout')                                                      # 5、登出用户
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])                             # 6、注册新用户
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
        'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required                                                             # 7、确认用户账号
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account.Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request                                                    # 8、全局请求的钩子，处理程序中过滤未确认的账户
def before_request():
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')                                                 # 9、显示一个确认账户的页面
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')                                                    # 10、请求重新发送邮件
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))