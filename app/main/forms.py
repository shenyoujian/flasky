#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:03
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :main蓝本中表单模块

from flask_wtf import Form
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField, ValidationError, PasswordField
from wtforms.validators import length, Email, regexp, DataRequired, EqualTo
from ..models import Role, User


class NameForm(Form):
    name = StringField('what is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')


# 用户级别的资料编辑表单
class EditProfileForm(Form):
    name = StringField('Real name', validators=[length(0, 64)])
    location = StringField('Location', validators=[length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')


# 管理员级别的资料编辑表单
class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[DataRequired(), length(1,64), Email()])
    username = StringField('Username', validators=[DataRequired(), length(0,64),
                                                   regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                          'Usernames must have only letters,'
                                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[length(0, 64)])
    location = StringField('Location', validators=[length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]

        self.user = user

    def validate_email(self, field):                                            # 自定义验证器
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


