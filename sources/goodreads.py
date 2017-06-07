from flask import Blueprint, request, redirect, url_for, flash, session
from flask.ext.login import login_required, current_user
from datetime import datetime
from db_functions import add_tags_to_doc, add_authors_to_doc
from requests_oauthlib import OAuth1Session
from xml.etree import ElementTree
from math import ceil
from config import g
from app import db
from models import Documents, Tokens

# goodreads uses Oauth1, returns xml
# source_id 2

### one issue with Goodreads: the API doesn't provide any way of determining
### books a user may have deleted from their shelves. That's probably not a big
### problem, but nonetheless I should see if this ever gets added.

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

#gets books info from goodreads and stores in database
def store_goodreads():

    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=2).first()

    #get Oauth object
    auth_object = OAuth1Session(g['client_id'],
                  client_secret=g['client_secret'],
                  resource_owner_key=tokens.access_token,
                  resource_owner_secret=tokens.access_token_secret)

    # always get books in the 'read' shelf
    get_books_from_shelf(auth_object, 'read')

    # possibly get books in the 'to-read' shelf as well
    if current_user.include_g_unread == 1:
        get_books_from_shelf(auth_object, 'to-read')

    return

# update book info from Goodreads
def update_goodreads():
    #unlike Mendeley, there doesn't appear to be a way to get books updated since X in goodreads,
    #so just have to delete and re-store all

    #delete
    Documents.query.filter_by(user_id=current_user.id, source_id=2).delete()

    #store
    store_goodreads()

    return

# this is the replacement for store_goodreads() and update_goodreads()
def import_goodreads(update_type):
    # get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=2).first()

    # get Oauth object
    auth_object = OAuth1Session(g['client_id'],
                  client_secret=g['client_secret'],
                  resource_owner_key=tokens.access_token,
                  resource_owner_secret=tokens.access_token_secret)

    # always get books in the 'read' shelf
    get_books_from_shelf(auth_object, 'read')

    # possibly get books in the 'to-read' shelf as well
    if current_user.include_g_unread == 1:
        get_books_from_shelf(auth_object, 'to-read')

    return

def get_books_from_shelf(auth_object, shelf):
    #first need to figure out how many pages, b/c limited to 200 items per call
    payload = {'v':'2', 'key':g['client_id'], 'shelf':shelf,
               'sort':'date_updated'}

    r = auth_object.get('https://www.goodreads.com/review/list.xml', params=payload)

    #if no docs found, return
    if r.status_code != 200:
        flash("You don't appear to have books on your Goodreads {} shelf.".format(shelf))
    else:
        docs = ElementTree.fromstring(r.content)

        #figure out how many pages of results
        total = docs[1].get('total')
        pages = ceil(int(total)/200)

        #go through each page (have to add one since page count doesn't start at 0)
        for i in range(1, pages+1):
            payload = {'v':'2', 'key':g['client_id'], 'shelf':shelf,
                    'per_page':'200', 'page':'{}'.format(i)}
            r = auth_object.get('https://www.goodreads.com/review/list.xml',
                            params=payload)

            #Goodreads returns xml response
            books = ElementTree.fromstring(r.content)

            # go through each doc, and see if we need to insert or update it
            for book in books[1]:
                save_doc(book, shelf)

        flash("Books on your Goodreads {} shelf have been updated.".format(shelf))

    current_user.goodreads_update = datetime.now()
    db.session.commit()
    return

# save book information
def save_doc(book, shelf):
    new_doc = Documents(2, book.find('book/title').text)
    current_user.documents.append(new_doc)
    new_doc.native_doc_id = book.find('id').text
    if shelf == 'read':
        new_doc.read = 1
    else:
        new_doc.read = 0

    # add date when created, convert from string to datetime object
    if book.find('read_at').text is not None:
        new_doc.created = datetime.strptime(book.find('read_at').text, '%a %b %d %H:%M:%S %z %Y')
    else:
        new_doc.created = datetime.strptime(book.find('date_added').text, '%a %b %d %H:%M:%S %z %Y')

    if book.find('book/published').text is not None:
        new_doc.year = book.find('book/published').text

    new_doc.link = book.find('book/link').text

    if book.find('date_updated').text is not None:
        new_doc.last_modified = datetime.strptime(book.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

    if book.find('body').text is not None:
        new_doc.note = book.find('body').text

    db.session.add(new_doc)
    db.session.commit()

    # add shelves as tags to the document
    if book.find('shelves/shelf') is not None:
        #make list of tags out of shelves this book is on
        tags = []
        for shelf in book.findall('shelves/shelf'):
            # don't add the 'read' shelf as a tag
            if shelf.get('name') == 'read':
                continue
            tags.append(shelf.get('name'))
            new_doc = add_tags_to_doc(tags, new_doc)

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

        new_doc = add_authors_to_doc(authors, new_doc)

    db.session.commit()

