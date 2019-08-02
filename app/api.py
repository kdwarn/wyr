"""
TODO:
    - might need to create get_user_doc() function to just get one doc, so I can put the exception
        there rather than manually do error checking for it elsewhere
    - paginate results for documents()
    - add endpoints for viewing user's tags, authors, and bunches
    - add endpoint for logging in?
    - send email notification to WYR that client registered
    - check that wyr.py is properly including register_client() and authorize() in CSRF
      protection (excluded these endpoints in the skipping of api blueprint)
    - allow developers to edit details of app
    - move api/clients to dev/clients?
    - make sure json response message/status/error messages are consistent
    - add endpoint for settings and preferences
"""

"""
    - user proper error response codes
        https://www.narwhl.com/http-response-codes/

    - list of error codes I'm using:
        1-9: db/account issues
            1: can't locate user
            2: can't locate client
            3: can't locate document
            4: no documents matching supplied criteria (tag, read_status, etc.)
        10-19: field issues
            10: title not supplied, but required
            11: link already exists in attempted added item
            12: No bunch by that name.
            13: not one of the user's items.
            14: ID not provided
            15: read_status has to be either "read' or 'to-read' if provided
        20-29: external source restrictions
            20: cannot edit Mendeley or Goodreads document
            21: cannot delete Mendely or Goodreads document
        90-99: authorization/submitted json issues
            90: Parameters not submitted in json format
            91: Missing token
            92: Invalid token
            93: Expired token
            94: Decode json/manipulated token error
            95: Username not supplied in API request
            96: Username in token does not match username supplied
            97: response_type must be set to authorization_code
            98: Client_id in token does not match client_id supplied.
            99: Other authorization/json issue

"""

"""
    Oauth2 resources:
        - RFC 6749: https://tools.ietf.org/html/rfc6749
"""


import datetime
from functools import wraps
import uuid

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
import jwt
from sqlalchemy.orm.exc import NoResultFound

from app import db
from . import common
from . import exceptions as ex
from .models import Documents, User, Client


api_bp = Blueprint("api", __name__)  # url prefix of /api set in init


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
    """Create both authorization code (in authorize()) and access token (in token())."""
    if not expiration:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    return jwt.encode(
        {"client_id": client_id, "username": user.username, "exp": expiration}, user.salt
    ).decode("utf-8")


def token_required(f):
    """
    Decorator for routes requiring tokens.

    First checks that request is in json format and returns error if not.

    If not able to authenticate token, returns error.

    Otherwise, returns calling function with user object and any *args and **kwargs passed.

    Based on https://prettyprinted.com/blog/9857/authenicating-flask-api-using-json-web-tokens
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return (
                jsonify({"message": "Parameters must be submitted in json format.", "error": 90}),
                400,
            )
        content = request.get_json()
        token = content.get("token")
        username = content.get("username")

        if not username:
            return jsonify({"message": "Username is missing", "error": 95}), 403

        if not token:
            return jsonify({"message": "Token is missing.", "error": 91}), 403

        # get the username - to then get user's salt, to verify signature below
        try:
            unverified_token = jwt.decode(token, verify=False)
        except jwt.exceptions.DecodeError as e:
            return jsonify({"message": str(e), "error": 94}), 403
        else:
            try:
                user = User.query.filter_by(username=unverified_token["username"]).one()
            except NoResultFound:
                return (jsonify({"message": "User could not be located.", "error": 1}), 404)

        # check that token sent is for the username sent
        if user.username != username:
            return jsonify({"message": "Token does not match user.", "error": 96}), 403

        # verify token with user's salt
        try:
            jwt.decode(token, user.salt)
        except jwt.exceptions.InvalidSignatureError as e:
            return jsonify({"message": str(e), "error": 92}), 403
        except jwt.exceptions.ExpiredSignatureError as e:
            return jsonify({"message": str(e), "error": 93}), 403
        except jwt.exceptions.DecodeError as e:
            return jsonify({"message": str(e), "error": 94}), 403
        except Exception as e:
            return jsonify({"message": str(e), "error": 99}), 403

        return f(user, *args, **kwargs)

    return wrapper


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

    return redirect(url_for("api.clients"))


@api_bp.route("/check_token", methods=["GET"])
@token_required
def check_token(user):
    """
    Provides verficiation to client developer that the token works (or doesn't).

    Token and username are fetched from request and validated via the @token_required decorator.
    All errors caught there. @t_r also returns *user*, which is not used here but is why it is
    included in function parameters.
    """
    return jsonify({"message": "Success! The token works.", "status": "Ok"}), 200


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

    """
    if request.method == "GET":
        client_id = request.args.get("client_id")
        response_type = request.args.get("response_type")
        state = request.args.get("state")

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

    client_id = request.form["client_id"]
    state = request.form["state"]

    try:
        client = Client.query.filter_by(client_id=client_id).one()
    except NoResultFound:
        flash("No third-party app found matching request.")
        return redirect(url_for("main.index"))

    current_user.apps.append(client)
    db.session.commit()
    print('test')

    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = create_token(current_user, client_id, expiration)
    redirect_url = client.callback_url + "?code=" + code

    if state:
        redirect_url += "&state=" + state

    return redirect(redirect_url, code=307)


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
        return (
            jsonify({"message": 'grant_type must be set to "authorization_code"', "error": 97}),
            400,
        )

    try:
        client = Client.query.filter_by(client_id=client_id).one()
    except NoResultFound:
        return jsonify({"message": "Client not found.", "error": 2}), 404

    # decode code without verifying signature, to get user and their salt for verification
    try:
        unverified_code = jwt.decode(code, verify=False)
    except jwt.exceptions.DecodeError as e:
        return jsonify({"message": str(e), "error": 94}), 403

    if unverified_code["client_id"] != client_id:
        return jsonify({"message": "Client does not match token.", "error": 98}), 403

    try:
        user = User.query.filter(User.username == unverified_code["username"]).one()
    except NoResultFound:
        return jsonify({"message": "Unable to locate user.", "error": 1}), 404

    # now verify signature
    try:
        jwt.decode(code, user.salt)
    except jwt.exceptions.InvalidSignatureError as e:
        return jsonify({"message": str(e), "error": 92}), 403
    except jwt.exceptions.ExpiredSignatureError as e:
        return jsonify({"message": str(e), "error": 93}), 403
    except jwt.exceptions.DecodeError as e:
        return jsonify({"message": str(e), "error": 94}), 400
    except Exception as e:
        return jsonify({"message": str(e), "error": 99}), 403

    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # TODO: change later
    token = create_token(user, client_id, expiration)
    user.apps.append(client)
    response = jsonify({"access_token": token, "token_type": "bearer"})
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
        return (jsonify({"message": "ID of document not included in request.", "error": 14}), 400)

    # get a document
    if request.method == "GET":
        try:
            doc = user.documents.filter(Documents.id == id).one()
        except NoResultFound:
            return jsonify({"message": "Unable to locate document.", "error": 3}), 404

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
                return (
                    jsonify({"message": "read_status should be 'read' or 'to-read'.", "error": 15}),
                    400,
                )
        try:
            docs = common.get_docs(
                user, tag=tag, author_id=author_id, bunch=bunch, read_status=read_status
            )
        except ex.NoBunchException:
            return (
                jsonify({"message": "No documents found matching supplied critieria.", "error": 4}),
                404,
            )

        if not docs:
            return (
                jsonify({"message": "No documents found matching supplied critieria.", "error": 4}),
                404,
            )

        docs_as_json = []
        for doc in docs:
            docs_as_json.append(doc.serialize())

        return jsonify(docs_as_json)
