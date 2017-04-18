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

#goodreads uses Oauth1, returns xml
#source_id 2

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
        goodreads = OAuth1Session(g['client_id'],
                          client_secret=g['client_secret'],
                          resource_owner_key=session['resource_owner_key'],
                          resource_owner_secret=session['resource_owner_secret'])

        #Goodreads doesn't (but is supposed to) send back a "verifier" value
        #the verifier='unused' hack I found at https://github.com/requests/requests-oauthlib/issues/115
        tokens = goodreads.fetch_access_token(g['access_token_url'], verifier='unused')

        #access token and access token secret
        access_token = tokens.get('oauth_token')
        access_token_secret = tokens.get('oauth_token_secret')

        #update User db record - flag them as Goodreads user
        current_user.goodreads = 1

        #save token in Tokens table
        tokens = Tokens(user_id=current_user.id, source_id=2, access_token=access_token, access_token_secret=access_token_secret)
        db.session.add(tokens)
        db.session.commit()

        store_goodreads()

        return redirect(url_for('index'))
    else:
        flash('Authorization failed.')
        return redirect(url_for('settings'))

#gets books info from goodreads and stores in database (only once, after initial authorization of source)
def store_goodreads():

    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=2).first()

    #get protected resource
    goodreads = OAuth1Session(g['client_id'],
              client_secret=g['client_secret'],
              resource_owner_key=tokens.access_token,
              resource_owner_secret=tokens.access_token_secret)

    #first need to figure out how many pages, because limited to 200 total in one call
    payload = {'v':'2', 'key':g['client_id'], } #just the required parameters parameters, no need for all

    r = goodreads.get('https://www.goodreads.com/review/list.xml', params=payload)


    #if no docs found, return
    if r.status_code != 200:
        flash('You don\'t appear to have any read books at Goodreads.')
        return redirect(url_for('settings'))

    g_docs = ElementTree.fromstring(r.content)

    #the reviews element has total count, figure out how many pages
    total = g_docs[1].get('total')
    pages = ceil(int(total)/200)
    i = 1

    #go through each page
    while i <= pages:
        payload = {'v':'2', 'key':g['client_id'], 'shelf':'read', 'per_page':'200', 'page':'{}'.format(i)}
        r = goodreads.get('https://www.goodreads.com/review/list.xml', params=payload)

        #Goodreads returns xml, not json, response
        g_docs = ElementTree.fromstring(r.content)

        #keep only those things we want, store in db
        for doc in g_docs[1]:
            new_doc = Documents(2, doc.find('book/title').text)
            current_user.documents.append(new_doc)
            new_doc.native_doc_id = doc.find('id').text
            new_doc.read = 1 #only requested books from read shelf

            #convert string to datetime object, prefer read_at but use date_added if not
            if doc.find('read_at').text is not None: # and doc.find('read_at').text != '':
                new_doc.created = datetime.strptime(doc.find('read_at').text, '%a %b %d %H:%M:%S %z %Y')
            else:
                new_doc.created = datetime.strptime(doc.find('date_added').text, '%a %b %d %H:%M:%S %z %Y')

            if doc.find('book/published').text is not None:
                new_doc.year = doc.find('book/published').text

            new_doc.link = doc.find('book/link').text

            if doc.find('date_updated').text is not None:
                new_doc.last_modified = datetime.strptime(doc.find('date_updated').text, '%a %b %d %H:%M:%S %z %Y')

            if doc.find('body').text is not None:
                new_doc.note = doc.find('body').text

            db.session.add(new_doc)
            db.session.commit()

            if doc.find('shelves/shelf') is not None:
                #make list of tags out of shelves this book is on
                tags = []
                for shelf in doc.findall('shelves/shelf'):
                    #these are all in 'read' shelf, don't add that as a tag
                    if shelf.get('name') == 'read':
                        continue
                    tags.append(shelf.get('name'))

                # add tags to the document
                new_doc = add_tags_to_doc(tags, new_doc)

            if doc.find('book/authors/author/name') is not None:
                #create list of dict of authors
                authors = []
                for name in doc.findall('book/authors/author/name'):
                    #split one full name into first and last (jr's don't work right now #to do)
                    new_name = name.text.rsplit(' ', 1)
                    authors.append({'first_name':new_name[0], 'last_name':new_name[1]})

                # add authors to doc
                new_doc = add_authors_to_doc(authors, new_doc)

        db.session.commit()

        i += 1

    current_user.goodreads_update = datetime.now()
    db.session.commit()
    return

#update doc info from Goodreads
def update_goodreads():
    #unlike Mendeley, there doesn't appear to be a way to get books updated since X in goodreads,
    #so just have to delete and re-store all

    #delete
    Documents.query.filter_by(user_id=current_user.id, source_id=2).delete()

    #store
    store_goodreads()

    flash('Documents from Goodreads have been refreshed.')
    return