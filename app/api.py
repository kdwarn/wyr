'''
    - user proper error response codes
        https://httpstatuses.com/
    - various things for app developers:

    - list of error codes I'm using:
        1-10: db/account issues
            1: can't locate user
            2: can't locate document
        10-20: field issues
            10: title not supplied, but required
            11: link already exists in attempted added item
            12: No bunch by that name.
            13: not one of the user's items.
        90-99: authorization/submitted json issues
            90: Parameters not submitted in json format
            91: Missing token
            92: Invalid token
            93: Expired token
            94: Decode json/manipulated token error
            99: Other authorization/json issue


TODO: combine add() and edit() (and delete(), not yet implmemented) into one endpoint

'''
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


api_bp = Blueprint('api', __name__)  # url prefix of /api set in init


def token_required(f):
    '''
    Decorator for routes requiring token authorization.
    If not able to authorize token, returns error. Otherwise, returns username
    and any *args and **kwargs passed from function being decorated.
    Based on https://prettyprinted.com/blog/9857/authenicating-flask-api-using-json-web-tokens
    '''

    @wraps(f)
    def wrapper(*args, **kwargs):

        if request.method == 'GET':
            token = request.args.get('token')
        elif request.method == 'POST' or request.method == 'PUT':
            if not request.is_json:
                return jsonify({'message': 'Parameters must be submitted in json format.'})
            content = request.get_json()
            token = content['token']

        if not token:
            return jsonify({'message' : 'Token is missing.', 'error': 91}), 403

        # get the username - to then get user's salt, to verify signature below
        try:
            payload = jwt.decode(token, verify=False)
        except jwt.exceptions.DecodeError as e:
            return jsonify({'message' : str(e), 'error': 94}), 400

        try:
            user = User.query.filter_by(username=payload['username']).one()
        except NoResultFound:
            return jsonify({'message' : 'User could not be located.', 'error': 1}), 404

        # verify jwt with user's salt
        try:
            jwt.decode(token, user.salt)
        except jwt.exceptions.InvalidSignatureError as e:
            return jsonify({'message' : str(e), 'error': 92}), 403
        except jwt.exceptions.ExpiredSignatureError as e:
            return jsonify({'message' : str(e), 'error': 93}), 403
        except jwt.exceptions.DecodeError as e:
            return jsonify({'message' : str(e), 'error': 94}), 400
        except Exception as e:
            return jsonify({'message' : str(e), 'error': 99}), 403

        # could return user object here, but not sure if there are security
        # vulnerabilities with doing that
        username = user.username
        return f(username, *args, **kwargs)
    return wrapper


@api_bp.route('register_client', methods=['GET', 'POST'])
def register_client():
    '''
    TODO: check that wyr.py is properly including this in csrf protection (added exclusion for 
        this and api.authorize)
    '''
    if request.method == 'GET':
        return render_template('register_client.html')
    
    submit = request.form['submit']

    if submit == 'register':
        id = uuid.uuid4().hex
        name = request.form['name']
        description = request.form['description']
        callback_url = request.form['callback_url']
        home_url = request.form['home_url']
        
        if not all([id, name, description, callback_url]):
            flash("Please complete all required fields.")
            return render_template('register_client.html')

        # check that id is unique
        clients = Client.query.all()
        if clients:
            client_ids = [client.id for client in clients]
            while id in client_ids:
                id = uuid.uuid4().hex

        client = Client(id, name, 'public', description, callback_url, home_url)
        db.session.commit()
    else:
        flash("Client registration canceled.")
        return render_template('register_client.html')


@api_bp.route('/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    '''
    Allow a user to authorize a client.
    TODO: check that wyr.py is properly including this in csrf protection (added exclusion for 
        this and api.authorize)
    '''

    if request.method == 'GET':
        return render_template('authorize_client.html')
    
    submit = request.form['submit']

    if submit == 'Yes':
        pass  # add record in user_clients (table)

    flash("Authorization not granted to Client.")
    return redirect(url_for('main.index'))




@api_bp.route('/token', methods=['POST'])
# @login_required
def token():
    '''Authenticates user and provides authorization token.'''
    client_id = ''
    grant_type = ''
    code = ''
    redirect_uri = ''

    

    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # TODO: change later
    token = jwt.encode({'username': current_user.username, 'exp': expiration}, current_user.salt)
    return jsonify({'token': token.decode('UTF-8')})


@api_bp.route('/check_token', methods=['GET'])
@token_required
def check_token(username):
    '''Verification that the token was provided.'''
    return jsonify({'message' : 'Success! The token works.',
                    'status': 'Ok'})


@api_bp.route('/document/<id>', methods=['GET'])
@token_required
def get(username, id):
    '''
    Get one document from user's collection.
    *username* is passed in from @token_required, if user's token is authorized.
    '''

    # no need to check valid username/user - will be caught in token_required
    user = User.query.filter_by(username=username).one()

    try:
        doc = user.documents.filter(Documents.id==id).one()
    except NoResultFound:
        return jsonify({'message': 'Unable to locate document.', 'error': 2}), 404

    if doc.tags:
        tags = [tag.name for tag in doc.tags]
    else:
        tags = ''

    if doc.authors:
        authors = [author.last_name + ', ' + author.first_name for author in doc.authors]
    else:
        authors = ''

    return jsonify({'title': doc.title,
                    'url': doc.link,
                    'year': doc.year,
                    'note': doc.note,
                    'tags': tags,
                    'authors': authors})


@api_bp.route('/document', methods=['POST'])
@token_required
def add(username):
    '''
    Add a document to user's account.
    *username* is passed in from @token_required, if user's token is authorized.
    '''

    if not request.is_json:
        return jsonify({'message' : 'Error with receiving data. Is it in json format?',
                        'error' : 90}), 400

    content = request.get_json()

    # no need to check valid username/user - will be caught in token_required
    user = User.query.filter_by(username=username).one()

    try:
        common.add_item(content, user, source='api')
    except ex.NoTitleException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    except ex.DuplicateLinkException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    else:
        return jsonify({'message': 'Success!'}), 200


@api_bp.route('/document/<id>', methods=['PUT'])
@token_required
def edit(username, id):
    '''
    Edit an existing doc.
    *username* is passed in from @token_required, if user's token is authorized.
    '''

    if not request.is_json:
        return jsonify({'message' : 'Error with receiving data. Is it in json format?',
                        'error' : 90}), 400

    content = request.get_json()
    content['id'] = id

    # no need to check valid username/user - will be caught in token_required
    user = User.query.filter_by(username=username).one()

    try:
        common.edit_item(content, user, source='api')
    except ex.NotUserDocException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    except ex.NoTitleException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    else:
        return jsonify({'message': 'Success!'}), 200



