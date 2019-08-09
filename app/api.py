"""
TODO:
    - send email notification to WYR that client registered
    - allow developers to edit details of app
    - allow users to revoke authorizations (in settings via main.py)
    - doc.serialize should return source_id so app can show source/users can know they can't edit
        those ones (this will need to be adding to specification, as well as the ref link to it)
    - paginate results for documents()
    - add endpoints for viewing user's tags, authors, and bunches
    - add endpoint for settings and preferences
"""

"""
    use proper error response codes: https://www.narwhl.com/http-response-codes/

    See https://www.whatyouveread.com/api/documentation for full documentation.

"""

import datetime
from functools import wraps
import uuid

from flask import (
    Blueprint,
    current_app,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user
import jwt
from sqlalchemy.orm.exc import NoResultFound

from app import db
from . import common
from . import exceptions as ex
from .models import Documents, User, Client


api_bp = Blueprint("api", __name__)  # url prefix of /api set in init

error_codes = {
    # 1-19: database/account errors
    "1": "Can't locate user",
    "2": "Can't locate client",
    "3": "Can't locate document",
    # 20-39: authorization or authorization code errors
    "20": "User has not authorized client or has revoked authorization",
    "21": "Invalid signature on authorization code",
    "22": "Authorization code has expired",
    "23": "Error decoding authorization code",
    "24": "Other authorization code decoding error",
    "25": "Grant_type must be set to 'authorization_code'",
    "26": "Client does not match code provided",
    # 40-59: access_token errors
    "40": "No Authorization Header provided",
    "41": "Authorization Header not in proper format",
    "42": "Authorization Header must be set to 'Bearer'",
    "43": "No token provided in Authorization Header",
    "44": "Erroring decoding access token",
    "45": "Invalid signature on access token",
    "46": "Access token has expired [Not implemented]",
    "47": "Other decoding access token error",
    # 60-79: Request paramaters and body errors
    "60": "Request body must be submitted in json format",
    "61": "ID not provided",
    "62": "title not supplied, but required",
    "63": "link already exists in attempted added item",
    "64": "Cannot edit Mendeley or Goodreads document",
    "65": "Cannot delete Mendely or Goodreads document",
    "66": "read_status has to be either 'read' or 'to-read' if provided",
    "67": "No documents matching supplied criteria (tag, read_status, etc.)",
}


def get_doc_content(id, content):
    """
    Return the doc fields from request (not auth-related fields).
    """
    return {
        "id": id,
        "title": content.get("title"),
        "link": content.get("link"),
        "tags": content.get("tags"),
        "authors": content.get("authors"),
        "year": content.get("year"),
        "notes": content.get("notes"),
        "read": content.get("read"),
    }


def create_token(user, client_id, expiration=""):
    """
    Create both authorization code (in authorize()) and access token (in token()).

    The .decode part returns the token as a string object rather than bytes.
    """
    if not expiration:
        return jwt.encode({"client_id": client_id, "username": user.username}, user.salt).decode(
            "utf-8"
        )

    return jwt.encode(
        {"client_id": client_id, "username": user.username, "exp": expiration}, user.salt
    ).decode("utf-8")


def token_required(f):
    """
    Decorator for routes requiring tokens.

    Return calling function with user object and any *args and **kwargs passed if no errors found
    in token provision.

    Based on https://prettyprinted.com/blog/9857/authenicating-flask-api-using-json-web-tokens
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"message": error_codes["40"], "error": 40}), 401

        try:
            auth_type, token = auth_header.split(" ", maxsplit=1)
        except ValueError:
            return (jsonify({"message": error_codes["41"], "error": 41}), 401)

        if auth_type != "Bearer":
            return (jsonify({"message": error_codes["42"], "error": 42}), 401)

        if not token:
            return (jsonify({"message": error_codes["43"], "error": 43}), 401)

        # get the username from the token, to then get user's salt, to verify signature below
        try:
            unverified_token = jwt.decode(token, verify=False)
        except jwt.exceptions.DecodeError as e:
            return jsonify({"message": str(e), "error": 44}), 401
        else:
            try:
                user = User.query.filter_by(username=unverified_token["username"]).one()
            except NoResultFound:
                return jsonify({"message": error_codes["1"], "error": 1}), 404

        try:
            user.apps.filter(Client.client_id == unverified_token["client_id"]).one()
        except NoResultFound:
            return (jsonify({"message": error_codes["20"], "error": 20}), 403)

        try:
            jwt.decode(token, user.salt)
        except jwt.exceptions.InvalidSignatureError as e:
            return jsonify({"message": str(e), "error": 45}), 401
        except jwt.exceptions.ExpiredSignatureError as e:
            return jsonify({"message": str(e), "error": 46}), 401
        except jwt.exceptions.DecodeError as e:
            return jsonify({"message": str(e), "error": 44}), 401
        except Exception as e:
            return jsonify({"message": str(e), "error": 47}), 401

        return f(user, *args, **kwargs)

    return wrapper


@api_bp.route("/documentation", methods=["GET"])
def api_doc():
    return render_template("api_documentation.html", error_codes=error_codes)


@api_bp.route("/clients", methods=["GET", "POST"])
@login_required
def clients():
    """
    Allow a user to register a client they developed and list their developed clients (not
    a list of clients that a user authorized - that will be in main.settings).

    Only registered users who are logged in can register clients.
    """
    if request.method == "GET":
        clients = Client.query.filter_by(user_id=current_user.id).all()
        return render_template("clients.html", clients=clients)

    if request.form["submit"] != "register":
        flash("Client registration canceled.")
    else:
        name = request.form.get("name")
        description = request.form.get("description")
        callback_url = request.form.get("callback_url")
        home_url = request.form.get("home_url")

        if not all([name, description, callback_url]):
            flash("Please complete all required fields.")
            return redirect(url_for("api.clients"))

        if not callback_url.startswith("https"):
            flash("The callback URL must use HTTPS.")
            return redirect(url_for("api.clients"))

        # create id, check that it is unique
        id = uuid.uuid4().hex
        clients = Client.query.all()
        if clients:
            client_ids = [client.client_id for client in clients]
            while id in client_ids:
                id = uuid.uuid4().hex

        client = Client(id, current_user.id, name, description, callback_url, home_url=home_url)
        db.session.add(client)
        db.session.commit()
        flash("Client registered.")

        if not current_app.testing:
            common.send_simple_message(
                "whatyouveread@protonmail.com",
                "New client created",
                f"User {current_user.username} created a client named {name}.",
            )

    return redirect(url_for("api.clients"))


@api_bp.route("/check_token", methods=["GET"])
@token_required
def check_token(user):
    """
    Provides verficiation to client developer that the token works (or doesn't).

    Token is fetched from request and validated via the @token_required decorator.
    All errors caught there. @t_r also returns *user*, which is not used here but is why it is
    included in function parameters.
    """
    return jsonify({"message": "Success! The token works."}), 200


@api_bp.route("/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    """
    Allow a user to authorize an app.

    In the Oauth2 protocol flow (https://tools.ietf.org/html/rfc6749#section-1.2), this is step A
    (Authorization Request) and step B (Authorization Grant).

    Third-party app sends user to this route with *client_id*, *response_type*, and (optional)
    *state* parameters in url (Authorization Request). If client_id matches registered app, then
    user is then presented with form to authorize the app.

    If user permits authorization, then they are redirected back to app's callback_url that was
    given at time of app creation, with an authorization code (jwt) and any state parameter passed
    to this route from client app (Authorization Grant).

    NOTE: the app is not associated with user.apps until the token has been properly retrieved.

    """
    if request.method == "GET":
        client_id = request.args.get("client_id")
        response_type = request.args.get("response_type")
        state = request.args.get("state", "")

        if response_type != "code":
            flash("Query parameter response_type must be set to 'code'. Authorization failed.")
            return redirect(url_for("main.index"))

        try:
            client = Client.query.filter_by(client_id=client_id).one()
        except NoResultFound:
            flash("No third-party app found matching request. Authorization failed.")
            return redirect(url_for("main.index"))

        return render_template(
            "authorize_app.html", client_name=client.name, client_id=client_id, state=state
        )

    if request.form["submit"] != "Yes":
        flash("Authorization not granted to app.")
        return redirect(url_for("main.index"))

    client_id = request.form.get("client_id")
    state = request.form.get("state")

    try:
        client = Client.query.filter_by(client_id=client_id).one()
    except NoResultFound:
        flash("No third-party app found matching request.")
        return redirect(url_for("main.index"))

    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = create_token(current_user, client_id, expiration)
    redirect_url = client.callback_url + "?code=" + code

    if state:
        redirect_url += "&state=" + state

    return redirect(redirect_url)


@api_bp.route("/token", methods=["POST"])
def token():
    """
    Return access token to client, after authorization from user.

    In the Oauth2 protocol flow (https://tools.ietf.org/html/rfc6749#section-1.2), this is step C
    (Authorization Grant) and Step D (Access Token). These steps would
    be better named Access Token Request and Access Token Grant. In Step C, the client provides
    the previously given Authorization Grant, WYR authenticates the client, and then provides the
    Access Token to the client.

    The client stores this access token for future calls to the user's protected resources (steps
    E and F, repeated as needed).
    """
    client_id = request.form["client_id"]
    grant_type = request.form["grant_type"]
    code = request.form["code"]

    if grant_type != "authorization_code":
        return (jsonify({"message": error_codes["25"], "error": 25}), 401)

    try:
        client = Client.query.filter_by(client_id=client_id).one()
    except NoResultFound:
        return jsonify({"message": error_codes["2"], "error": 2}), 404

    # decode code without verifying signature, to get user and their salt for verification
    try:
        unverified_code = jwt.decode(code, verify=False)
    except jwt.exceptions.DecodeError as e:
        return jsonify({"message": str(e), "error": 23}), 401

    if unverified_code["client_id"] != client_id:
        return jsonify({"message": error_codes["26"], "error": 26}), 401

    try:
        user = User.query.filter(User.username == unverified_code["username"]).one()
    except NoResultFound:
        return jsonify({"message": error_codes["1"], "error": 1}), 404

    # now verify signature
    try:
        jwt.decode(code, user.salt)
    except jwt.exceptions.InvalidSignatureError as e:
        return jsonify({"message": str(e), "error": 21}), 401
    except jwt.exceptions.ExpiredSignatureError as e:
        return jsonify({"message": str(e), "error": 22}), 401
    except jwt.exceptions.DecodeError as e:
        return jsonify({"message": str(e), "error": 23}), 401
    except Exception as e:
        return jsonify({"message": str(e), "error": 24}), 401

    # only add app is user hasn't already authorized it
    try:
        user.apps.filter_by(client_id=client.client_id).one()
    except NoResultFound:
        user.apps.append(client)
        db.session.commit()

    access_token = create_token(user, client_id)
    response = jsonify({"access_token": access_token, "token_type": "bearer"})
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return response, 200


@api_bp.route("/documents/<id>", methods=["GET", "PUT", "DELETE"])
@token_required
def document(user, id):
    """
    Get, edit, or delete one document from user's collection.

    All error checking of token/username, json format is done by @token_required, which also
    returns *user* to this function.
    """
    if not id:
        return (jsonify({"message": error_codes["61"], "error": 61}), 400)

    try:
        doc = user.documents.filter(Documents.id == id).one()
    except NoResultFound:
        return jsonify({"message": error_codes["3"], "error": 3}), 404

    # get a document
    if request.method == "GET":
        return jsonify(doc.serialize()), 200

    # edit a document
    if request.method == "PUT":
        doc_content = get_doc_content(id, request.get_json())

        try:
            common.edit_item(doc_content, user, source="api")
        except ex.NotUserDocException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        except ex.NotEditableDocException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        except ex.NoTitleException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        else:
            return jsonify({"message": "Item edited."}), 200

    # delete document
    if request.method == "DELETE":
        try:
            common.delete_item(id, user, source="api")
        except ex.NotDeleteableDocException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        except ex.NotUserDocException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        else:
            return jsonify({"message": "Item deleted."}), 200


@api_bp.route("/documents", methods=["GET", "POST"])
@token_required
def documents(user, tag="", author_id="", bunch="", read_status=""):
    """
    Get all documents from a user's collection or add a new document.

    All error checking of token/username, json format is done by @token_required, which also
    returns *user* to this function.
    """

    # add a document
    if request.method == "POST":
        if not request.is_json:
            return (jsonify({"message": error_codes["60"], "error": 60}), 400)

        doc_content = get_doc_content(id, request.get_json())

        try:
            common.add_item(doc_content, user, source="api")
        except ex.NoTitleException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        except ex.DuplicateLinkException as e:
            return jsonify({"message": str(e.message), "error": e.error}), e.http_status
        else:
            return jsonify({"message": "Item added."}), 201

    # get all documents
    if request.method == "GET":
        tag = request.args.get("tag")
        author_id = request.args.get("author_id")
        bunch = request.args.get("bunch")
        read_status = request.args.get("read_status")

        if read_status:
            if read_status not in ["read", "to-read"]:
                return (jsonify({"message": error_codes["66"], "error": 66}), 400)
        try:
            docs = common.get_docs(
                user, tag=tag, author_id=author_id, bunch=bunch, read_status=read_status
            )
        except ex.NoBunchException:
            return (jsonify({"message": error_codes["67"], "error": 67}), 404)

        if not docs:
            return (jsonify({"message": error_codes["67"], "error": 67}), 404)

        docs_as_json = []
        for doc in docs:
            docs_as_json.append(doc.serialize())

        return jsonify(docs_as_json)
