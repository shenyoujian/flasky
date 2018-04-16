#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:03
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :main蓝本中定义程序路由

from datetime import datetime
from flask import render_template, session, redirect, url_for

from .import main
from .forms import NameForm
from .. import db
from .. models import User


@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        return redirect(url_for('.index'))
    return render_template('index.html',
                           form=form, name=session.get('name'),
                           known=session.get('known', False),
                           current_time=datetime.utcnow())