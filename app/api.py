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


'''
import datetime
from functools import wraps

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import jwt
from sqlalchemy.orm.exc import NoResultFound

from . import common
from . import exceptions as ex
from .models import Documents, User


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


@api_bp.route('/get_token', methods=['GET'])
@login_required
def get_token():
    '''Authenticates user and provides authorization token.'''
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



# @api_blueprint.route('/api/document/<id>', methods=['DELETE'])
# @token_required
# def delete():
#     if request.method == 'GET':
#         # check that doc is one of current_user's
#         id = request.args.get('id', '')
#         doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).first()

#         if doc:
#             read_status = 'to-read' if doc.read == 0 else 'read'

#             return render_template('delete.html', doc=doc, read_status=read_status)
#         else:
#             return redirect(url_for('index'))
#     elif request.method == 'POST':
#         delete = request.form['delete']
#         id = request.form['id']
#         if delete == 'Cancel':
#             flash("Item not deleted.")
#             return return_to_previous()

#         if delete == 'Delete':
#             # delete doc
#             doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).one()

#             # delete docs tags
#             for tag in doc.tags:
#                 doc.tags.remove(tag)

#             # delete docs authors
#             for author in doc.authors:
#                 doc.authors.remove(author)

#             # delete it
#             doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).delete()

#             db.session.commit()


