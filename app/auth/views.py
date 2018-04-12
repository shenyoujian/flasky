#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:32
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :auth蓝本中的路由和视图函数

from flask import render_template
from . import auth                                  #1、引入蓝本

@auth.route('/login')                               #2、使用蓝本的route修饰器定义与认证相关的路由
def login():
    return render_template('auth/login.html')