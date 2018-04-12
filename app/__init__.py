#!/usr/bin/python3
# @Time    : 2018/4/10 19:03
# @Author  : shenyoujian
# @Email   : shenyoujian2@163.com
# @description :程序工厂函数

from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    #在工厂函数中注册蓝本
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    #附加路由和自定义的错误页面

    return app

