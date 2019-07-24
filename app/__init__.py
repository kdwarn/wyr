import datetime
from random import random
import re

from flask import Flask, session
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_misaka import Misaka
from flask_caching import Cache
from jinja2 import evalcontextfilter, Markup, escape

##################################################
# START-UP FUNCTIONS USED IN WYR.APP AND TESTING #
##################################################

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = random()
    return session['_csrf_token']


def datetimeformat(value, format='%B %d, %Y'):
    ''' display datetime like May 1, 1886'''
    value = datetime.datetime.fromtimestamp(value)
    return value.strftime(format)


@evalcontextfilter
def nl2br(eval_ctx, value):
    ''' New lines to breaks. '''
    _paragraph_re = re.compile(r'(?:\r\n|\r|\n){2,}')
    result = u'\n\n'.join(u'<p>%s</p>' % p.replace('\n', Markup('<br>\n'))
                          for p in _paragraph_re.split(escape(value)))
    if eval_ctx.autoescape:
        result = Markup(result)
    return result

###################################
# INIT EVERYTHING AND APP FACTORY #
###################################

db = SQLAlchemy()
login = LoginManager()
login.login_view = 'main.login'
md = Misaka(autolink=True, underline=True, strikethrough=True, no_html=True, 
             highlight=True, hard_wrap=True, fenced_code=True)

cache = Cache(config={'CACHE_TYPE': 'simple'})


def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login.init_app(app)
    md.init_app(app)
    cache.init_app(app)

    # import blueprints
    from .main import bp as main_bp
    from .native import native_bp
    from .mendeley import mendeley_bp
    from .goodreads import goodreads_bp
    from .api import api_bp

    #register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(native_bp)
    app.register_blueprint(mendeley_bp)
    app.register_blueprint(goodreads_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    return app


