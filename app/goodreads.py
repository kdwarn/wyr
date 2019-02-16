import datetime
import math
import pytz
from xml.etree import ElementTree

from flask import Blueprint, request, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from requests_oauthlib import OAuth1Session

from app import db
from .common import add_tags_to_doc, add_authors_to_doc, \
    remove_old_tags, remove_old_authors, send_simple_message
from .models import Documents, Tokens


# goodreads uses Oauth1, returns xml
# source_id 2

goodreads_bp = Blueprint('goodreads', __name__)

@goodreads_bp.route('/goodreads')
@login_required
def goodreads_login():
    goodreads_config = current_app.config['GOODREADS_CONFIG']

    goodreads = OAuth1Session(goodreads_config['client_id'], client_secret=goodreads_config['client_secret'])

    fetch_response = goodreads.fetch_request_token(goodreads_config['request_token_url'])

    session['resource_owner_key'] = fetch_response.get('oauth_token')
    session['resource_owner_secret'] = fetch_response.get('oauth_token_secret')
    authorization_url = goodreads.authorization_url(goodreads_config['authorize_url'])

    return redirect(authorization_url)

@goodreads_bp.route('/goodreads/authorization')
@login_required
def goodreads_authorize():

    goodreads_config = current_app.config['GOODREADS_CONFIG']

    authorize = request.args.get('authorize')

    if authorize == '1':
        #get access token
        auth_object = OAuth1Session(goodreads_config['client_id'],
                      client_secret=goodreads_config['client_secret'],
                      resource_owner_key=session['resource_owner_key'],
                      resource_owner_secret=session['resource_owner_secret'])

        # Goodreads doesn't (but is supposed to) send back a "verifier" value
        # the verifier='unused' hack I found at
        # https://github.com/requests/requests-oauthlib/issues/115
        tokens = auth_object.fetch_access_token(goodreads_config['access_token_url'],
                                              verifier='unused')

        #access token and access token secret
        access_token = tokens.get('oauth_token')
        access_token_secret = tokens.get('oauth_token_secret')

        #update User db record - flag them as Goodreads user
        current_user.goodreads = 1

        #save token in Tokens table
        tokens = Tokens(user_id=current_user.id,
                        source_id=2,
                        access_token=access_token,
                        access_token_secret=access_token_secret)

        db.session.add(tokens)
        db.session.commit()

        flash("Authorization successful.")
        return redirect(url_for('main.verify_authorization', source='Goodreads'))

    else:
        flash('Authorization failed.')
        return redirect(url_for('main.settings'))

def import_goodreads(update_type):
    '''Connect to Goodreads and initiate process of collecting info.'''

    goodreads_config = current_app.config['GOODREADS_CONFIG']

    try:
        # get tokens from Tokens table
        tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=2).first()

        # get Oauth object
        auth_object = OAuth1Session(goodreads_config['client_id'],
                      client_secret=goodreads_config['client_secret'],
                      resource_owner_key=tokens.access_token,
                      resource_owner_secret=tokens.access_token_secret)

        # get books in the 'read' shelf unless this is an unread_update
        if update_type != 'unread_update':
            get_books_from_shelf(auth_object, 'read', update_type)

        # get books in the 'to-read' shelf if user wants them
        if current_user.include_g_unread == 1:
            get_books_from_shelf(auth_object, 'to-read', update_type)
    except Exception as e:
        to = 'whatyouveread@gmail.com'
        subject = 'Error updating Goodreads'
        text = 'An exception ({}) has occurred while attempting to update Goodreads.'.format(e)
        send_simple_message(to, subject, text)
        flash('An error has occurred while attempting to update the books on '
            'your Goodreads bookshelves. We will fix this as soon as possible.')
    return

def get_books_from_shelf(auth_object, shelf, update_type):
    goodreads_config =  current_app.config['GOODREADS_CONFIG']

    ''' Get Books from shelf, determine what to do with them.'''

    # first need to figure out how many pages, b/c limited to 200 items per call
    payload = {'v':'2', 'key':goodreads_config['client_id'], 'shelf':shelf,
               'sort':'date_updated'}

    r = auth_object.get('https://www.goodreads.com/review/list.xml', params=payload)

    #if no books found, return
    if r.status_code != 200:
        flash("You don't appear to have books on your Goodreads {} shelf.".format(shelf))
    else:
        root = ElementTree.fromstring(r.content)

        # figure out how many pages of results
        total = root[2].get('total')
        pages = math.ceil(int(total)/200)

        book_ids = [] # list to determine if any books were deleted

        # go through each page
        for i in range(1, pages+1):  # add one since page count doesn't start at 0

            payload = {'v':'2', 'key':goodreads_config['client_id'], 'shelf':shelf,
                    'per_page':'200', 'page':'{}'.format(i)}
            r = auth_object.get('https://www.goodreads.com/review/list.xml',
                            params=payload)

            # Goodreads returns xml response
            root = ElementTree.fromstring(r.content)

            # go through each book, and see if we need to insert/update it
            for review in root[2]:  # root[2] is *reviews* top-level xml

                if update_type == 'initial':
                    save_doc(review, shelf)

                else:
                    if update_type == 'normal':

                        # add the book's native id to a list (to check for deleted)
                        book_ids.append(review.find('id').text)

                        date_updated = datetime.datetime.strptime(review.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

                        # *date_updated* is in local time, convert to UTC, remove timezone
                        date_updated = date_updated.astimezone(pytz.utc).replace(tzinfo=None)

                        if date_updated < current_user.goodreads_update:
                            # book not updated
                            # we could exit here, but need ids to check for deleted docs
                            continue

                    # pass along any existing doc to save function
                    check_doc = Documents.query.filter_by(user_id=current_user.id,
                        source_id=2, native_doc_id=review.find('id').text).first()

                    save_doc(review, shelf, check_doc)

        if update_type == 'normal':
            delete_books(book_ids)

        flash("Books on your Goodreads {} shelf have been updated.".format(shelf))

    current_user.goodreads_update = datetime.datetime.now(pytz.utc)
    db.session.commit()
    return

def save_doc(book, shelf, existing_doc=""):
    '''
    Save book (insert or update in db) and any authors and tags.

    book -- book object from goodreads
    shelf -- the Goodreads shelf ('to-read' or 'read')
    existing_doc -- doc object from WYR Document object (implying an update)
    '''

    if not existing_doc: # inserting, create Document object
        doc = Documents(2, book.find('book/title').text)
        current_user.documents.append(doc)
        doc.native_doc_id = book.find('id').text # this is actually review id
    else: # updating, Document object already exists
        doc = existing_doc

    # until the db.session.commit, code is the same whether insert or update
    doc.read = 1 if shelf == 'read' else 0

    # add date when created, convert from string to datetime object
    if book.find('read_at').text is not None:
        created = datetime.datetime.strptime(book.find('read_at').text, '%a %b %d %H:%M:%S %z %Y')

        # *created* is in local time, convert to UTC, remove timezone
        doc.created = created.astimezone(pytz.utc).replace(tzinfo=None)

    else:
        created = datetime.datetime.strptime(book.find('date_added').text, '%a %b %d %H:%M:%S %z %Y')

        # *created* is in local time, convert to UTC, remove timezone
        doc.created = created.astimezone(pytz.utc).replace(tzinfo=None)


    if book.find('book/published').text is not None:
        doc.year = book.find('book/published').text

    doc.link = book.find('book/link').text

    if book.find('date_updated').text is not None:
        last_modified = datetime.datetime.strptime(book.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

        # *last_modified* is in local time, convert to UTC, remove timezone
        doc.last_modified = last_modified.astimezone(pytz.utc).replace(tzinfo=None)


    if book.find('body').text is not None:
        doc.note = book.find('body').text

    db.session.add(doc)
    db.session.commit()

    # inserting
    if not existing_doc:
        # add shelves as tags to the document
        if book.find('shelves/shelf') is not None:
            #make list of tags out of shelves this book is on
            tags = []
            for shelf in book.findall('shelves/shelf'):
                # don't add the 'read' or 'to-read' shelves as a tag
                if shelf.get('name') == 'read' or shelf.get('name') == 'to-read':
                    continue
                tags.append(shelf.get('name'))
                doc = add_tags_to_doc(tags, doc)

        # add authors to the document
        if book.find('book/authors/author/name') is not None:
            #create list of dict of authors
            authors = []
            for name in book.findall('book/authors/author/name'):
                #split one full name into first and last (jr's don't work right now #to do)
                new_name = name.text.rsplit(' ', 1)
                try:
                    authors.append({'first_name':new_name[0], 'last_name':new_name[1]})
                except IndexError:
                    authors.append({'first_name':'', 'last_name':new_name[0]})

            doc = add_authors_to_doc(authors, doc)

    # updating
    else:
        tags = []
        for shelf in book.findall('shelves/shelf'):
            # don't add the 'read' or 'to-read' shelves as a tag
            if shelf.get('name') == 'read' or shelf.get('name') == 'to-read':
                continue
            tags.append(shelf.get('name'))

        # remove_old_tags takes list of names, not tag objects, so:
        old_tags = [tag.name for tag in doc.tags]
        if old_tags:
            doc, tags = remove_old_tags(old_tags, tags, doc)

        # add any new tags to doc
        if tags:
            doc = add_tags_to_doc(tags, doc)

        # authors
        if book.find('book/authors/author/name') is not None:
            #create list of dict of authors
            authors = []
            for name in book.findall('book/authors/author/name'):
                #split one full name into first and last (jr's don't work right now #to do)
                new_name = name.text.rsplit(' ', 1)
                try:
                    authors.append({'first_name':new_name[0], 'last_name':new_name[1]})
                except IndexError:
                    authors.append({'first_name':'', 'last_name':new_name[0]})
        else:
            authors = ''

        old_authors = [{'first_name':author.first_name,
                        'last_name':author.last_name}
                        for author in doc.authors]

        if old_authors:
            doc, authors = remove_old_authors(old_authors, authors, doc)

        if authors:
            doc = add_authors_to_doc(authors, doc)

    db.session.commit()

def delete_books(book_ids):
    '''Remove deleted books from db.'''

    books = Documents.query.filter_by(user_id=current_user.id, source_id=2).all()

    for book in books:
        if book.native_doc_id not in book_ids:
            Documents.query.filter_by(user_id=current_user.id, source_id=2, native_doc_id=book.native_doc_id).delete()

