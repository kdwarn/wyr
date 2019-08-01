from flask import session, url_for, request, redirect

from app import create_app, datetimeformat, nl2br, generate_csrf_token
from config import Config


wyr_app = create_app(Config)

################
# HTTPS REDIRECT
################


@wyr_app.before_request
def https_redirect():
    if request.url.startswith("http://"):
        url = request.url.replace("http://", "https://", 1)
        code = 301
        return redirect(url, code=code)


#################
# CSRF PROTECTION
#################

# from http://flask.pocoo.org/snippets/3/
# must use  <input name="_csrf_token" type="hidden" value="{{ csrf_token() }}"> in template forms
@wyr_app.before_request
def csrf_protect():

    # don't add csrf protection for API calls, except authorizing and registering a client
    if request.blueprint == "api" and request.endpoint not in [
        "api.authorize",
        "api.register_client",
    ]:
        return

    if request.method == "POST":
        token = session.pop("_csrf_token", None)
        if not token or "{}".format(token) != request.form.get("_csrf_token"):
            return redirect(url_for("main.index"))


wyr_app.jinja_env.globals["csrf_token"] = generate_csrf_token

###############
# JINJA FILTERS
###############

wyr_app.jinja_env.filters["datetime"] = datetimeformat
wyr_app.jinja_env.filters["nl2br"] = nl2br
