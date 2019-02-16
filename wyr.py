import datetime
from random import random
import re

from flask import session, url_for, request, redirect
from jinja2 import evalcontextfilter, Markup, escape

from app import create_app


wyr_app = create_app()


####################################
# CHANGE JINJA CACHING TO DICTIONARY
####################################

# https://blog.socratic.org/the-one-weird-trick-that-cut-our-flask-page-load-time-by-70-87145335f679

#wyr_app.jinja_env.cache = {}


################
# HTTPS REDIRECT
################

@wyr_app.before_request
def https_redirect():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)


#################
# CSRF PROTECTION
#################

#from http://flask.pocoo.org/snippets/3/
#must use  <input name="_csrf_token" type="hidden" value="{{ csrf_token() }}"> in template forms
@wyr_app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or "{}".format(token) != request.form.get('_csrf_token'):
            return redirect(url_for('main.index'))


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = random()
    return session['_csrf_token']

wyr_app.jinja_env.globals['csrf_token'] = generate_csrf_token

###############
# JINJA FILTERS
###############

def datetimeformat(value, format='%B %d, %Y'):
    ''' display datetime like May 1, 1886'''
    value = datetime.datetime.fromtimestamp(value)
    return value.strftime(format)
wyr_app.jinja_env.filters['datetime'] = datetimeformat


@evalcontextfilter
def nl2br(eval_ctx, value):
    ''' New lines to breaks. '''
    _paragraph_re = re.compile(r'(?:\r\n|\r|\n){2,}')
    result = u'\n\n'.join(u'<p>%s</p>' % p.replace('\n', Markup('<br>\n'))
                          for p in _paragraph_re.split(escape(value)))
    if eval_ctx.autoescape:
        result = Markup(result)
    return result
wyr_app.jinja_env.filters['nl2br'] = nl2br
