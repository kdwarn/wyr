'''
TODO:
    - test api.add_item and api.add
    - implement api.edit next
    - user proper error response codes
        https://httpstatuses.com/
    - various things for app developers: callback urls(?), ...

    - list of error codes I'm using:
        1-10: db/account issues
            1: can't locate user
            2: can't locate document
        10-20: field issues
            10: title not supplied, but required
            11: link already exists in attempted added item
            12: read status not within parameters (0-1)
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
        # if coming from WYR forms, no need to check token
        # if current_user.is_authenticated:
        #     return f(current_user.username, *args, **kwargs)

        if request.method == 'GET':
            token = request.args.get('token')
        elif request.method == 'POST':
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

    doc = user.documents.filter(Documents.id==id).first()

    if not doc:
        return jsonify({'message': 'Unable to locate document.', 'error': 2}), 404

    return jsonify({'title': doc.title,
                    'url': doc.link})


@api_bp.route('/document', methods=['POST'])
@token_required
def add(username):
    print(username)
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
        common.add_item(content, user)
    except ex.NoTitleException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    except ex.DuplicateLinkException as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    except ex.BadReadValueError as e:
        return jsonify({'message': str(e.message), 'error': str(e.error)}), e.http_status
    else:
        return jsonify({'message': 'Success!'}), 200


# @api_blueprint.route('document/<id>', methods=['PUT'])
# @token_required
# def edit():
#     if request.method == 'GET':
#         # check that doc is one of current_user's
#         id = request.args.get('id', '')

#         doc = current_user.documents.filter(Documents.id==id).first()

#         if doc:
#             new_tags = ''
#             new_authors_list = []
#             new_authors = ''

#             # have to format tags and authors for form
#             if doc.tags:
#                 # put names into list to sort
#                 super_new_tag_list=[tag.name for tag in doc.tags]
#                 super_new_tag_list.sort() # sort
#                 for name in super_new_tag_list:
#                     if name != super_new_tag_list[-1]:
#                         new_tags += name + ', '
#                     else:
#                         new_tags += name

#             if doc.authors:
#                 for author in doc.authors:
#                     new_authors_list.append(author)

#             for author in new_authors_list:
#                 if author != new_authors_list[-1]:
#                     new_authors += author.last_name + ', ' + author.first_name + '; '
#                 else:
#                     new_authors += author.last_name + ', ' + author.first_name

#             # also pass along all tags and authors for autocomplete
#             all_tags = get_user_tag_names()
#             all_authors = get_user_author_names()

#             return render_template('add.html', edit=1, doc=doc, tags=new_tags,
#                 all_tags=all_tags, all_authors=all_authors, authors=new_authors)
#         else:
#             return redirect(url_for('index'))

#     elif request.method == 'POST':
#         id = request.form['id']
#         title = request.form['title']
#         link = request.form['link']
#         year = request.form['year']
#         tags = request.form['tags']
#         old_tags = request.form['old_tags']
#         authors = request.form['authors']
#         old_authors = request.form['old_authors']
#         notes = request.form['notes']
#         submit = request.form['submit']

#         # validation
#         if not title:
#             flash('Please enter a title. It is the only required field.')
#             return redirect(url_for('native.edit'))

#         # update
#         update_doc = current_user.documents.filter(Documents.source_id==3, Documents.id==id).first()
#         update_doc.title = title

#         # add http:// if not there or else will be relative link within site
#         if link:
#             if 'http://' not in link and 'https://' not in link:
#                 link = 'http://' + link

#         update_doc.link = link
#         update_doc.year = year
#         update_doc.note = notes

#         # if change from to-read to read, updated created, delete last_modified
#         if update_doc.read == 0 and submit == 'read':
#             update_doc.created = datetime.now(pytz.utc)
#             update_doc.last_modified = ''
#         else:
#             update_doc.last_modified = datetime.now(pytz.utc)

#         update_doc.read = 0 if submit == 'unread' else 1

#         # update tags
#         # turn strings of tags into lists of tags
#         tags = str_tags_to_list(tags)
#         old_tags = str_tags_to_list(old_tags)
#         # if there were old tags, remove those no longer associated with doc,
#         # update the doc and also return updated list of tags
#         if old_tags:
#             update_doc, tags = remove_old_tags(old_tags, tags, update_doc)
#         # add any new tags to doc
#         if tags:
#             update_doc = add_tags_to_doc(tags, update_doc)

#         # update authors
#         authors = str_authors_to_list(authors)
#         old_authors = str_authors_to_list(old_authors)
#         if old_authors:
#             update_doc, authors = remove_old_authors(old_authors, authors,
#                 update_doc)
#         if authors:
#             update_doc = add_authors_to_doc(authors, update_doc)

#         db.session.commit()


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


