from flask import Blueprint, request, redirect, url_for, flash, session
from flask.ext.login import login_required, current_user
from datetime import datetime
import pytz
from db_functions import add_tags_to_doc, add_authors_to_doc, remove_old_tags, \
    remove_old_authors
from requests_oauthlib import OAuth1Session
from xml.etree import ElementTree
from math import ceil
from config import g
from app import db
from models import Documents, Tokens

# goodreads uses Oauth1, returns xml
# source_id 2

goodreads_blueprint = Blueprint('goodreads', __name__, template_folder='templates')

@goodreads_blueprint.route('/goodreads')
@login_required
def goodreads_login():
    goodreads = OAuth1Session(g['client_id'], client_secret=g['client_secret'])

    fetch_response = goodreads.fetch_request_token(g['request_token_url'])

    session['resource_owner_key'] = fetch_response.get('oauth_token')
    session['resource_owner_secret'] = fetch_response.get('oauth_token_secret')
    authorization_url = goodreads.authorization_url(g['authorize_url'])

    return redirect(authorization_url)

@goodreads_blueprint.route('/goodreads/authorization')
@login_required
def goodreads_authorize():

    authorize = request.args.get('authorize')

    if authorize == '1':
        #get access token
        auth_object = OAuth1Session(g['client_id'],
                      client_secret=g['client_secret'],
                      resource_owner_key=session['resource_owner_key'],
                      resource_owner_secret=session['resource_owner_secret'])

        # Goodreads doesn't (but is supposed to) send back a "verifier" value
        # the verifier='unused' hack I found at
        # https://github.com/requests/requests-oauthlib/issues/115
        tokens = auth_object.fetch_access_token(g['access_token_url'],
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
        return redirect(url_for('verify_authorization', source='Goodreads'))

    else:
        flash('Authorization failed.')
        return redirect(url_for('settings'))

def import_goodreads(update_type):
    '''Connect to Goodreads and initiate process of collecting info.'''

    # get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=2).first()

    # get Oauth object
    auth_object = OAuth1Session(g['client_id'],
                  client_secret=g['client_secret'],
                  resource_owner_key=tokens.access_token,
                  resource_owner_secret=tokens.access_token_secret)

    # get books in the 'read' shelf unless this is an unread_update
    if update_type != 'unread_update':
        get_books_from_shelf(auth_object, 'read', update_type)

    # get books in the 'to-read' shelf if user wants them
    if current_user.include_g_unread == 1:
        get_books_from_shelf(auth_object, 'to-read', update_type)

    return

def get_books_from_shelf(auth_object, shelf, update_type):
    ''' Get Books from shelf, determine what to do with them.'''

    # first need to figure out how many pages, b/c limited to 200 items per call
    payload = {'v':'2', 'key':g['client_id'], 'shelf':shelf,
               'sort':'date_updated'}

    r = auth_object.get('https://www.goodreads.com/review/list.xml', params=payload)

    #if no books found, return
    if r.status_code != 200:
        flash("You don't appear to have books on your Goodreads {} shelf.".format(shelf))
    else:
        docs = ElementTree.fromstring(r.content)

        #figure out how many pages of results
        total = docs[1].get('total')
        pages = ceil(int(total)/200)

        exit_loop = 0 # iniate var that determinds when to stop an update

        book_ids = [] # list to determine if any books were deleted

        #go through each page (have to add one since page count doesn't start at 0)
        for i in range(1, pages+1):

            if exit_loop == 1: # set in nested for loop, for an update
                break

            payload = {'v':'2', 'key':g['client_id'], 'shelf':shelf,
                    'per_page':'200', 'page':'{}'.format(i)}
            r = auth_object.get('https://www.goodreads.com/review/list.xml',
                            params=payload)

            #Goodreads returns xml response
            books = ElementTree.fromstring(r.content)

            # go through each book, and see if we need to insert/update it
            for book in books[1]:
                if update_type == 'initial':
                    save_doc(book, shelf)

                else:
                    #add the book's native id to a list (to check for deleted)
                    book_ids.append(book.find('id').text)

                    # if normal update, break out of loop if book updated before last refresh
                    if update_type == 'normal':
                        date_updated = datetime.strptime(book.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

                        # *date_updated* is in local time, convert to UTC, remove timezone
                        date_updated = date_updated.astimezone(pytz.utc).replace(tzinfo=None)

                        if date_updated < current_user.goodreads_update:
                            # book not updated
                            # we could exit here, but need ids to check for deleted docs
                            continue

                    # pass along any existing doc to save function
                    check_doc = Documents.query.filter_by(user_id=current_user.id,
                        source_id=2, native_doc_id=book.find('id').text).first()

                    save_doc(book, shelf, check_doc)

        delete_books(book_ids)

        flash("Books on your Goodreads {} shelf have been updated.".format(shelf))

    current_user.goodreads_update = datetime.now(pytz.utc)
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
        doc.created = datetime.strptime(book.find('read_at').text, '%a %b %d %H:%M:%S %z %Y')
    else:
        doc.created = datetime.strptime(book.find('date_added').text, '%a %b %d %H:%M:%S %z %Y')

    if book.find('book/published').text is not None:
        doc.year = book.find('book/published').text

    doc.link = book.find('book/link').text

    if book.find('date_updated').text is not None:
        doc.last_modified = datetime.strptime(book.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

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
                # don't add the 'read' shelf as a tag
                if shelf.get('name') == 'read':
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
            # don't add the 'read' shelf as a tag
            if shelf.get('name') == 'read':
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


