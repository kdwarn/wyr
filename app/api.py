'''
TODO: 
    - NEXT: test what i have so far; 
    - send email notification to WYR that client registered
    - check that wyr.py is properly including register_client() and authorize() in CSRF
      protection (excluded these endpoints in the skipping of api blueprint)
    - combine add() and edit() (and delete(), not yet implmemented) into one endpoint
    - allow developers to edit details of app
    - move api/clients to dev/clients?
'''

'''
    - user proper error response codes
        https://httpstatuses.com/

    - list of error codes I'm using:
        1-10: db/account issues
            1: can't locate user
            2: can't locate client
            3: can't locate document
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

'''
import datetime
from functools import wraps
import random
import string
import uuid

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
import jwt
import requests
from sqlalchemy.orm.exc import NoResultFound

from app import db
from . import common
from . import exceptions as ex
from .models import Documents, User, Client


api_bp = Blueprint('api', __name__)  # url prefix of /api set in init


def create_token(user, client_id, expiration=''):
    ''' Create token for authorization code and access token.'''
    if not expiration:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    token = jwt.encode({'client_id': client_id, 
                        'username': user.username, 
                        'exp': expiration,
                        }, 
                        user.salt).decode('utf-8')
    return token


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
            unverified_token = jwt.decode(token, verify=False) 
        except jwt.exceptions.DecodeError as e:
            return jsonify({'message' : str(e), 'error': 94}), 400
        else:
            try:
                user = User.query.filter_by(username=unverified_token['username']).one()
            except NoResultFound:
                return jsonify({'message' : 'User could not be located.', 'error': 1}), 404

        # verify token with user's salt
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


@api_bp.route('/clients', methods=['GET', 'POST'])
@login_required
def clients():
    '''View developer's clients and register a client.
    Only registered and logged-in users can create clients.
    '''
    
    if request.method == 'GET':
        clients = Client.query.filter_by(user_id=current_user.id).all()
        return render_template('clients.html', clients=clients)
    
    if request.form['submit'] != 'register':
        flash("Client registration canceled.")
    else:  
        name = request.form.get('name')
        description = request.form.get('description')
        callback_url = request.form.get('callback_url')
        home_url = request.form.get('home_url')
        
        if not all([name, description, callback_url]):
            flash("Please complete all required fields.")
            return redirect(url_for('api.clients'))

        if not callback_url.startswith('https'):
            flash("The callback URL must use HTTPS.")
            return redirect(url_for('api.clients'))

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
        
    return render_template('clients.html')


@api_bp.route('/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    '''Allow a user to authorize an app.'''

    if request.method == 'GET':
        client_id = request.args.get('client_id')
        response_type = request.args.get('response_type')
        state = request.args.get('state')

        if response_type != 'code':
            flash("Query parameter response_type must be set to 'code'. Authorization failed.")
            return redirect(url_for('main.index'))
        
        try:
            client = Client.query.filter(client_id=client_id).one()
        except NoResultFound:
            flash("No third-party app found matching request. Authorization failed.")
            return redirect(url_for('main.index'))
        
        return render_template('authorize_app.html', 
                               client_name=client.name, 
                               client_id=client.id,
                               state=state)
    
    if request.form['submit'] != 'Yes':
        flash("Authorization not granted to app.")
        return redirect(url_for('main.index'))
    
    client_id = request.form['client_id']
    state = request.form['state']
    
    try:
        client = Client.query.filter_by(client_id=client_id).one()
    except NoResultFound:
        flash("No third-party app found matching request.")
        return redirect(url_for('main.index'))
    
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = create_token(current_user, client_id, expiration) 
    
    redirect_url = client.callback_url + '?code=' + code

    if state:
        redirect_url += '&state=' + state
    
    return redirect(redirect_url, code=307)
        

@api_bp.route('/token', methods=['POST'])
def token():
    '''Provide authorization token to client.'''
    client_id = request.form['client_id']
    grant_type = request.form['grant_type']
    code = request.form['code']

    if grant_type != 'authorization_code':
        #TODO: choose correct http response
        return jsonify({'message' : 'grant_type must be set to "authorization_code"'}), 403

    # decode code without verifying signature, to get user and their salt for verification
    try:
        unverified_code = jwt.decode(code, verify=False) 
    except jwt.exceptions.DecodeError as e:
        return jsonify({'message' : str(e), 'error': 94}), 400
    
    if unverified_code['client_id'] != client_id:
        return jsonify({'message': 'Unable to locate client.', 'error': 2}), 404

    try:
        user = User.query.filter(User.username==unverified_code['username']).one()
    except NoResultFound:
        return jsonify({'message': 'Unable to locate user.', 'error': 1}), 404

    # now verify signature
    try:
        jwt.decode(code, user.salt)
    except jwt.exceptions.InvalidSignatureError as e:
        return jsonify({'message' : str(e), 'error': 92}), 403
    except jwt.exceptions.ExpiredSignatureError as e:
        return jsonify({'message' : str(e), 'error': 93}), 403
    except jwt.exceptions.DecodeError as e:
        return jsonify({'message' : str(e), 'error': 94}), 400
    except Exception as e:
        return jsonify({'message' : str(e), 'error': 99}), 403
    
    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # TODO: change later
    token = create_token(user, client_id, expiration)

    client = Client.query.filter_by(client_id=client_id).one()
    user.apps.append(client)

    # return jsonify({'access_token': token, 'token_type': 'bearer'}), 200
    response = jsonify({'access_token': token, 
                        'token_type': 'bearer'})
    # response.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response, 200
 


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
        return jsonify({'message': 'Unable to locate document.', 'error': 3}), 404

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
    Test
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



