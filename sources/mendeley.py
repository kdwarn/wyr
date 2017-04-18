from flask import Blueprint, request, redirect, url_for, flash, session
from flask.ext.login import login_required, current_user
from datetime import datetime
from db_functions import get_user_tag, add_tags_to_doc, add_authors_to_doc, \
    remove_old_tags, remove_old_authors
from app import db
from models import Documents, Tags, Tokens, FileLinks
from requests_oauthlib import OAuth2Session
from config import m
from time import time
from oauthlib.oauth2 import InvalidGrantError

# Mendeley uses Oauth 2, returns json
# source_id = 1
# this uses requests-oauthlib:
# https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow
# mendely documentation:
# http://dev.mendeley.com/reference/topics/authorization_overview.html

mendeley_blueprint = Blueprint('mendeley', __name__, template_folder='templates')

@mendeley_blueprint.route('/mendeley')
@login_required
def mendeley_login():

    mendeley = OAuth2Session(client_id=m['client_id'], redirect_uri=m['redirect_uri'], scope=m['scope'])
    authorization_url, state = mendeley.authorization_url(m['authorize_url'])

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

@mendeley_blueprint.route('/mendeley/authorization')
@login_required
def mendeley_authorize():
    # get vars from redirect
    code = request.args.get('code')
    state = request.args.get('state')

    # check against CSRF attacks
    if state != session['oauth_state']:
        return "Sorry, there has been an error."

    mendeley = OAuth2Session(m['client_id'], state=session['oauth_state'], redirect_uri=m['redirect_uri'])
    token = mendeley.fetch_token(m['token_url'], code=code, username=m['client_id'], password=m['client_secret'])

    #save token in Tokens table
    tokens = Tokens(user_id=current_user.id, source_id=1, access_token=token['access_token'], refresh_token=token['refresh_token'])
    db.session.add(tokens)
    db.session.commit()

    return store_mendeley()

#gets doc info from mendeley and stores in database (only once, after initial authorization of source)
def store_mendeley():
    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=1).first()

    #0Auth2Session requires that its token parameter is in a dict
    token = {'access_token':tokens.access_token,
             'refresh_token':tokens.refresh_token}

    #get new 0auth object with new token
    mendeley = OAuth2Session(m['client_id'], token=token)

    #parameters
    payload = {'limit':'500', 'order':'desc', 'sort':'created', 'view':'all'}

    r = mendeley.get('https://api.mendeley.com/documents', params=payload)
    m_docs = r.json()

    #if no docs found, return
    if r.status_code != 200:
        return flash('You don\'t appear to have any read documents in Mendeley.')

    #Mendeley will not get all results, so have to go through pages. If there
    #are more results after first page, Mendeley provides a "next" link - this
    #pulls that out of the .headers['link'], strips out non-link characters,
    #and calls it
    if 'link' in r.headers:
        while 'rel="next"' in r.headers['link']:
            mendeley_link = r.headers['link'].split('>')
            mendeley_link = mendeley_link[0].strip('<')
            r = mendeley.get(mendeley_link)
            m_docs = m_docs + r.json() #add new list of docs to old one


    #keep only those things we want, store in db
    for doc in m_docs:
        # skip items not read if user doesn't want them - user can set this pref
        # after Mendeley is authorized, and then get them with update function
        if current_user.include_m_unread == 0:
            if doc['read'] == 0:
                continue

        new_doc = Documents(1, doc['title'])
        current_user.documents.append(new_doc)

        new_doc.created=doc['created']
        new_doc.read=doc['read']
        new_doc.starred=doc['starred']
        new_doc.native_doc_id = doc['id']

        if 'year' in doc:
            new_doc.year = doc['year']
        if 'last_modified' in doc:
            new_doc.last_modified=doc['last_modified']

        #Mendeley allows multiple links, but only include first one
        if 'websites' in doc:
            new_doc.link = doc['websites'][0]

        #get notes
        an_params = {'document_id':doc['id'], 'type':'note'}
        annotations = mendeley.get('https://api.mendeley.com/annotations', params=an_params).json()
        if annotations:
            new_doc.note = annotations[0]['text']

        db.session.add(new_doc)
        db.session.commit()

        # add tags to the document
        if 'tags' in doc:
            new_doc = add_tags_to_doc(doc['tags'], new_doc)

        # add authors to the document
        if 'authors' in doc:
            new_doc = add_authors_to_doc(doc['authors'], new_doc)

        """
        # skip editors for now - need to restructure database
        if 'editors' in doc:
            for editor in doc['editors']:
                try:
                    new_editor = Authors(editor['first_name'], editor['last_name'], 1)
                except KeyError:
                    try:
                        new_editor = Authors('', editor['last_name'], 1)
                    except KeyError:
                        new_editor = Authors(editor['first_name'], '', 1)
                db.session.add(new_editor)
        """

        #get file id to link to
        file_params = {'document_id':doc['id']}
        files = mendeley.get('https://api.mendeley.com/files', params=file_params).json()

        if files:
            for file in files:
                new_filelink = FileLinks(new_doc.id, file['id'])
                new_filelink.mime_type = file['mime_type']
                db.session.add(new_filelink)

        db.session.commit()

    current_user.mendeley = 1
    current_user.mendeley_update = datetime.now()
    db.session.commit()

    return redirect(url_for('index'))

#update doc info from Mendeley
def update_mendeley():
    # get user's "to-read" Tag object, if any, in order to later tag unread items
    to_read_tag = get_user_tag('to-read')

    #get existing tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, source_id=1).first()

    #0Auth2Session requires that its token parameter is in a dict
    token = {'access_token':tokens.access_token,
             'refresh_token':tokens.refresh_token}

    token['expires_in'] = time() - 10

    extra = {'client_id': m['client_id'],
             'client_secret': m['client_secret'],
             'refresh_token': tokens.refresh_token}

    #these next 20 lines or so are not what requests_oauthlib suggested, but they work

    #get 0auth object
    mendeley = OAuth2Session(m['client_id'], token=token)

    #get new access token (and possibly refresh token)
    try:
        new_token = mendeley.refresh_token(m['refresh_url'], **extra)
    except InvalidGrantError:
        flash('''There is a problem with your Mendeley authorization. If you
            changed your Mendeley password recently, try to de-authorize and then
            re-authorize Mendeley in your settings. If you continue to get this
            error, please contact me for help.''')
        return redirect(url_for('settings'))

    #resave
    tokens.access_token = new_token['access_token']
    tokens.refresh_token = new_token['refresh_token']
    db.session.commit()

    #get new 0auth object with new token
    mendeley = OAuth2Session(m['client_id'], token=new_token)

    # covert last time mendeley was updated to iso format (8601)
    modified_since = current_user.mendeley_update.isoformat()

    #parameters
    payload = {'limit':'500', 'view':'all', 'modified_since':modified_since}

    r = mendeley.get('https://api.mendeley.com/documents', params=payload)
    m_docs = r.json()

    #if no docs found, don't do anything
    if r.status_code != 200:
        pass

    else:
        #Mendeley will not get all results, so have to go through pages. If there
        #are more results after first page, Mendeley provides a "next" link - this
        #pulls that out of the .headers['link'], strips out non-link characters,
        #and calls it
        if 'link' in r.headers:
            while 'rel="next"' in r.headers['link']:
                mendeley_link = r.headers['link'].split('>')
                mendeley_link = mendeley_link[0].strip('<')
                r = mendeley.get(mendeley_link)
                m_docs = m_docs + r.json() #add new list of docs to old one

        # go through each doc, and see if we need to insert or update it
        for doc in m_docs:

            #skip items not read if user doesn't want them
            if current_user.include_m_unread == 0 and doc['read'] == 0:
                continue

            #see if the doc is already in the db
            check_doc = Documents.query.filter_by(user_id=current_user.id, source_id=1, native_doc_id=doc['id']).first()

            #if not in db, insert it
            if not check_doc:
                new_doc = Documents(1, doc['title'])
                current_user.documents.append(new_doc)
                new_doc.created=doc['created']
                new_doc.read=doc['read']
                new_doc.starred=doc['starred']
                new_doc.native_doc_id=doc['id']

                if 'year' in doc:
                    new_doc.year = doc['year']
                if 'last_modified' in doc:
                    new_doc.last_modified=doc['last_modified']

                #Mendeley allows multiple links, but only include first one
                if 'websites' in doc:
                    new_doc.link = doc['websites'][0]

                #get notes
                an_params = {'document_id':doc['id'], 'type':'note'}
                annotations = mendeley.get('https://api.mendeley.com/annotations', params=an_params).json()
                if annotations:
                    new_doc.note = annotations[0]['text']

                db.session.add(new_doc)
                db.session.commit()

                # if unread, tag as "to-read" - and we might have to create this tag
                if doc['read'] == 0:
                    if to_read_tag != None:
                        new_doc.tags.append(to_read_tag)
                    else:
                        new_tag = Tags('to-read')
                        new_doc.tags.append(new_tag)

                # add normal tags to the document
                if 'tags' in doc:
                    new_doc = add_tags_to_doc(doc['tags'], new_doc)

                # add authors to the document
                if 'authors' in doc:
                    new_doc = add_authors_to_doc(doc['authors'], new_doc)

                """
                #skip editors for now
                if 'editors' in doc:
                    for editor in doc['editors']:
                        try:
                            new_editor = Authors(current_user.id, new_doc.id, editor['first_name'], editor['last_name'], 1)
                        except KeyError:
                            try:
                                new_editor = Authors(current_user.id, new_doc.id, '', editor['last_name'], 1)
                            except KeyError:
                                new_editor = Authors(current_user.id, new_doc.id, editor['first_name'], '', 1)
                        db.session.add(new_editor)
                """

                #get file id to link to
                file_params = {'document_id':doc['id']}
                files = mendeley.get('https://api.mendeley.com/files', params=file_params).json()

                if files:
                    for file in files:
                        new_filelink = FileLinks(new_doc.id, file['id'])
                        new_filelink.mime_type = file['mime_type']
                        db.session.add(new_filelink)
                    db.session.commit()

            #else, update it
            else:
                # convert last_modified to datetime object and check if newer
                # than one in db (no need to update if not)
                check_date = datetime.strptime(doc['last_modified'], "%Y-%m-%dT%H:%M:%S.%fZ")

                if check_date > check_doc.last_modified:
                    check_doc.title = doc['title']
                    check_doc.created=doc['created']
                    check_doc.read=doc['read']
                    check_doc.starred=doc['starred']
                    check_doc.last_modified=doc['last_modified']

                    if 'year' in doc:
                        check_doc.year = doc['year']

                    #Mendeley allows multiple links, but only include first one
                    if 'websites' in doc:
                        check_doc.link = doc['websites'][0]

                    #get notes
                    an_params = {'document_id':doc['id'], 'type':'note'}
                    annotations = mendeley.get('https://api.mendeley.com/annotations', params=an_params).json()
                    if annotations:
                        check_doc.note = annotations[0]['text']

                    db.session.commit()

                    # if unread, tag as "to-read"
                    if doc['read'] == 0:
                        if to_read_tag != None:
                            check_doc.tags.append(to_read_tag)
                        else:
                            new_tag = Tags('to-read')
                            check_doc.tags.append(new_tag)


                    # update tags
                    #set tags variable so it can be used below, even if empty
                    try:
                        tags = doc['tags']
                    except KeyError:
                        tags = ''
                    # remove old tags, update tags
                    # remove_old_tags takes list of names, not tag objects, so:
                    old_tags = [tag.name for tag in check_doc.tags]
                    if old_tags:
                        check_doc, tags = remove_old_tags(old_tags, tags, check_doc)
                    # add any new tags to doc
                    if tags:
                        check_doc = add_tags_to_doc(tags, check_doc)


                    # update authors, same pattern as for tags
                    try:
                        authors = doc['authors']
                    except KeyError:
                        authors = ''
                    old_authors = [{'first_name':author.first_name,
                                    'last_name':author.last_name}
                                   for author in check_doc.authors]
                    if old_authors:
                        check_doc, authors = remove_old_authors(old_authors,
                            authors, check_doc)
                    if authors:
                        check_doc = add_authors_to_doc(authors, check_doc)

                    """do editors later - need to restructure database
                    if 'editors' in doc:
                        for editor in doc['editors']:
                            try:
                                new_editor = Authors(current_user.id, check_doc.id, editor['first_name'], editor['last_name'], 1)
                            except KeyError:
                                try:
                                    new_editor = Authors(current_user.id, check_doc.id, '', editor['last_name'], 1)
                                except KeyError:
                                    new_editor = Authors(current_user.id, check_doc.id, editor['first_name'], '', 1)
                            db.session.add(new_editor)
                            db.session.commit()
                    """

                    # update file_links
                    old_file_links = check_doc.file_links
                    # get file id to link to
                    file_params = {'document_id':doc['id']}
                    files = mendeley.get('https://api.mendeley.com/files', params=file_params).json()

                    # one scenario not caught by "if files:" below: there were old files, but no
                    # new files (user deleted one/all). Have to treat this separately.
                    if old_file_links and not files:
                        for old_file_link in old_file_links:
                            check_doc.file_links.remove(old_file_link)

                    if files:
                        #create list of file_ids to check against
                        file_ids = [file['id'] for file in files]

                        # check old file list against files submitted after edit, remove any no longer there
                        if old_file_links:
                            for old_file_link in old_file_links:
                                if old_file_link.file_link not in file_ids:
                                    check_doc.file_links.remove(old_file_link)

                            #don't add files if they were already in old_files - would be a duplicate
                            for file in files[:]:
                                if file['id'] in file_ids:
                                    files.remove(file)

                        #add new files
                        for file in files:
                            new_filelink = FileLinks(check_doc.id, file['id'])
                            new_filelink.mime_type = file['mime_type']
                            db.session.add(new_filelink)

                    db.session.commit()

    # now, get all documents deleted from Mendeley since last update & delete
    # parameters
    payload = {'limit':'500', 'deleted_since':modified_since, 'include_trashed':'true'}
    r = mendeley.get('https://api.mendeley.com/documents', params=payload)
    m_docs = r.json()

    #if no docs found, don't do anything
    if r.status_code != 200:
        pass
    else:
        #Mendeley will not get all results, so have to go through pages. If there
        #are more results after first page, Mendeley provides a "next" link - this
        #pulls that out of the .headers['link'], strips out non-link characters,
        #and calls it
        if 'link' in r.headers:
            while 'rel="next"' in r.headers['link']:
                mendeley_link = r.headers['link'].split('>')
                mendeley_link = mendeley_link[0].strip('<')
                r = mendeley.get(mendeley_link)
                m_docs = m_docs + r.json() #add new list of docs to old one

        # delete each doc
        for doc in m_docs:
            Documents.query.filter_by(user_id=current_user.id, source_id=1, native_doc_id=doc['id']).delete()

        db.session.commit()

    current_user.mendeley_update = datetime.now()
    db.session.commit()

    flash('Documents from Mendeley have been refreshed.')
    return

# if user has changed pref from including to excluding unread items, delete them
def remove_to_read_mendeley():
    to_read_tag = get_user_tag('to-read')

    if to_read_tag != None:
        # delete all docs with to-read as tag
        current_user.documents.filter(Documents.source_id==1, Documents.tags.any(name=to_read_tag.name)).delete(synchronize_session='fetch')

        db.session.commit()
    return
