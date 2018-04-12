#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:03
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :与用户认证系统相关的路由可在auth蓝本中定义。

from flask import Blueprint

auth = Blueprint('auth',__name__)             #1、蓝本的包构造文件创建蓝本对象
from . import views                           #2、再从views.py模块中引入路由