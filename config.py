# -*- coding:utf-8 -*-

class Config(object):
    SECRET_KEY = "Ay98Cct2oNSlnHDdTl8"
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

    @staticmethod
    def init_app(app):
        pass

class LastConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:123456@localhost:3306/dbtest"


class TestConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:123456@localhost:3306/test_data"


config = {'default':LastConfig, 'test':TestConfig}