#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/15 13:49
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :登录和注册表单

from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField

from wtforms.validators import DataRequired, Email, Length, regexp, EqualTo, length
from app.models import User
from wtforms import ValidationError


# 登录表单
class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])

    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


# 注册表单
class RegistrationForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64),
                                                   regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                          'Usernames must have only letters.'
                                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        DataRequired(), EqualTo('password2', message='Password must match.')])

    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    # 如果表单类中定义了以validate_开头并且后面跟着字段名的方法，这个方法和验证函数Validators一起调用。
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise  ValidationError('Username already in use.')


# 修改密码表单
class ChangePasswordForm(Form):
    old_password = PasswordField('Old password', validators=[DataRequired()])
    password = PasswordField('New password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm new password',
                              validators=[DataRequired()])
    submit = SubmitField('Update Password')


# 忘记密码，填写邮箱找回密码表单
class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')


# 忘记密码，重设密码表单
class PasswordResetForm(Form):
    password = PasswordField('New Password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


# 修改邮箱表单
class ChangeEmailForm(Form):
    email = StringField('New Email', validators=[DataRequired(), length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
