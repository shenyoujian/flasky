#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2018/4/10 19:03
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :创建蓝本

from flask import Blueprint
from app.models import Permission


main = Blueprint('main', __name__)

from .import views, errors  # 这必须放到最后


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)