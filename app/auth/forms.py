#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/15 13:49
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :登录和注册表单

from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Email, Length, regexp, EqualTo
from app.models import User
from wtforms import ValidationError


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])

    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64),
                                                   regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                          'Usernames must have only letters.'
                                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Password must match.')])

    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    # 如果表单类中定义了以validate_开头并且后面跟着字段名的方法，这个方法和验证函数Validators一起调用。
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise  ValidationError('Username already in use.')

