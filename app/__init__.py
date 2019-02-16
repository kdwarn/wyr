from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_misaka import Misaka
from flask_caching import Cache

from config import Config


db = SQLAlchemy()
login = LoginManager()
login.login_view = 'main.login'
md = Misaka(autolink='true', underline='true', strikethrough='true', html='false',
            no_html='true', highlight='true', hardwrap='true', wrap='true',
            fenced_code='true')
cache = Cache(config={'CACHE_TYPE': 'simple'})


def create_app(config_class=Config):
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

    # if not app.debug and not app.testing:
    #     if app.config['MAIL_SERVER']:
    #         auth = None
    #         if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
    #             auth = (app.config['MAIL_USERNAME'],
    #                     app.config['MAIL_PASSWORD'])
    #         secure = None
    #         if app.config['MAIL_USE_TLS']:
    #             secure = ()
    #         mail_handler = SMTPHandler(
    #             mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
    #             fromaddr='no-reply@' + app.config['MAIL_SERVER'],
    #             toaddrs=app.config['ADMINS'], subject='Microblog Failure',
    #             credentials=auth, secure=secure)
    #         mail_handler.setLevel(logging.ERROR)
    #         app.logger.addHandler(mail_handler)

    #     if not os.path.exists('logs'):
    #         os.mkdir('logs')
    #     file_handler = RotatingFileHandler('logs/microblog.log',
    #                                       maxBytes=10240, backupCount=10)
    #     file_handler.setFormatter(logging.Formatter(
    #         '%(asctime)s %(levelname)s: %(message)s '
    #         '[in %(pathname)s:%(lineno)d]'))
    #     file_handler.setLevel(logging.INFO)
    #     app.logger.addHandler(file_handler)

    return app


