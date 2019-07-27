import datetime

from flask import flash, current_app, session, redirect, url_for
from flask_login import current_user
import pytz
import requests
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from app import db
from .models import Tags, Authors, Documents, Bunches, SourceToken, document_tags, document_authors
from . import exceptions as ex


def return_to_previous():
    ''' redirect user back to last page prior to edit or delete (or cancel) '''

    if 'return_to' in session:
        return redirect(session['return_to'])
    return redirect(url_for('main.index'))


def get_docs(user, read_status='', tag='', author_id='', bunch=''):
    ''' Get user documents filtered in various ways.'''

    filters = []

    if read_status == 'to-read':
        filters.append(Documents.read==0)
    if read_status == 'read':
        filters.append(Documents.read==1)
    if tag:
        filters.append(Documents.tags.any(name=tag))
    if author_id:
        filters.append(Documents.authors.any(id=author_id))
    if bunch:
            # get the name, tags, read_status, and selector for this bunch
            try:
                bunch = Bunches.query.filter(Bunches.user_id==user.id, Bunches.name==bunch).one()
            except NoResultFound:
                raise ex.NoBunchException
            else:
                if bunch.selector == 'or':
                    filters.append(Documents.tags.any(Tags.id.in_([t.id for t in bunch.tags])))
                if bunch.selector == 'and':
                    for tag in bunch.tags:
                        filters.append(Documents.tags.any(id=tag.id))

    docs = user.documents.filter(*filters).order_by(desc(Documents.created)).all()

    return docs


###############
# TAG FUNCTIONS
###############

def get_user_tags(user):
    '''Gets user's tags, as objects, in alphabetical order by tag.name.'''

    tags = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id).order_by(Tags.name).all()

    return tags


def get_user_tag(user, tag_name):
    '''Get one tag object.'''

    try:
        tag = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id, Tags.name==tag_name).one()
    except NoResultFound:
        raise
    else:
        return tag


def add_or_update_tags(user, tags, doc):

    # rename tags to submitted_tags for clarity and to ensure whitespace stripped
    submitted_tags = [tag.strip() for tag in tags]  # names

    # remove any tags associated with this doc if not in new tags submitted with edit
    if doc.tags:
        for associated_tag in doc.tags[:]:
            if associated_tag.name not in submitted_tags:
                doc.tags.remove(associated_tag)

    # add any tags not already associated with it (and possibly create new Tag)
    for submitted_tag in submitted_tags[:]:
        if submitted_tag not in [tag.name for tag in doc.tags]:

            # not doing the duplicate check - could actually be a worse
            # error if removing space from a tag results in a completely
            # different tag/word

            try:
                existing_tag = get_user_tag(user, submitted_tag)
            except NoResultFound:
                new_tag = Tags(submitted_tag)
                doc.tags.append(new_tag)
            else:
                doc.tags.append(existing_tag)

    return


def delete_orphaned_tags():
    '''Delete all orphaned tags for all users.'''

    orphaned_tags_sql = "delete from tags where id not in (select tag_id from document_tags)"
    db.session.execute(orphaned_tags_sql)


##################
# AUTHOR FUNCTIONS
##################

# functions converting various author input formats into standard dict with keys
# last_name, first_name are in the specific modules where necessary

def get_user_authors(user):
    '''Get user's authors.'''

    authors = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id).order_by(Authors.last_name).all()

    return authors


def get_user_author(user, first_name, last_name):
    '''Get one of the user's authors.'''

    try:
        author = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id, \
                Authors.first_name==first_name, Authors.last_name==last_name).one()
    except NoResultFound:
        raise
    else:
        return author


# Authors_nt = namedtuple('Authors_nt', ['last_name', 'first_name'])


def add_or_update_authors(user, submitted_authors, doc):
    '''
    Add authors to doc or update authors associated with doc.

    Input: **authors** is list of authors as dict with keys first_name, last_name
    Output: none, doc.authors is updated.
    '''

    # whitespace has already been stripped

    # remove any authors associated with this doc if not in new authors submitted with edit
    if doc.authors:
        for author in [{'last_name': author.last_name, 'first_name': author.first_name} for author in doc.authors]:
            if author not in submitted_authors:
                author_to_remove = get_user_author(user, author['first_name'], author['last_name'])
                doc.authors.remove(author_to_remove)

    # add any new authors to this doc
    for submitted_author in submitted_authors:
        # add in empty values for keys if they are missing
        submitted_author['first_name'] = submitted_author.get('first_name', '')
        submitted_author['last_name'] = submitted_author.get('last_name', '')

        if submitted_author not in [{'last_name': author.last_name, 'first_name': author.first_name} for author in doc.authors]:
            try:
                existing_author = get_user_author(user, submitted_author['first_name'], submitted_author['last_name'])
            except NoResultFound:
                new_author = Authors(submitted_author['first_name'], submitted_author['last_name'])
                doc.authors.append(new_author)
            else:
                doc.authors.append(existing_author)

    return


def delete_orphaned_authors():
    '''Delete orphaned authors for all users.'''

    orphaned_authors_sql = "delete from authors where id not in (select author_id from document_authors)"
    db.session.execute(orphaned_authors_sql)


#############################
# ADD, EDIT, AND DELETE ITEMS
#############################

def add_item(content, user, source=''):
    '''Add document to database.'''

    # uses source rather than source_id because there is a difference in how
    # items from native.py and api.py are treated, although same source_id

    if source == 'mendeley':  # mendeley code doesn't yet send data to this function
        source_id = 1
    elif source == 'goodreads':
        source_id = 2
    else:
        source_id = 3  # native WYR docs, from native or api

    title = content.get('title')
    link = content.get('link')
    tags = content.get('tags')
    authors = content.get('authors')
    year = content.get('year')
    notes = content.get('notes')

    if content.get('read') in [0, '0', 1, '1']:
        read = int(content.get('read'))
    else:
        read = 1  # default to read if value is anything else

    if not title:
        raise ex.NoTitleException

    if source_id == 3 and link:
        # add "http://" if not there or else will be relative link within site
        if 'http://' not in link and 'https://' not in link:
            link = 'http://' + link

        doc = user.documents.filter_by(link=link, source_id=source_id).first()

        if doc:
            raise ex.DuplicateLinkException(doc.id)

    created = datetime.datetime.now(pytz.utc)

    doc = Documents(user.id, source_id, title, link=link, year=year, notes=notes, read=read,
                    created=created)

    if tags:
        add_or_update_tags(user, tags, doc)

    if authors:
        add_or_update_authors(user, authors, doc)

    if source in ['goodreads', 'mendeley']:
        doc.native_doc_id = content['native_doc_id']

    user.documents.append(doc)

    db.session.commit()

    return


def edit_item(content, user, source=''):
    '''Edit existing document.'''
    # uses source rather than source_id because there is a difference in how
    # items from native.py and api.py are treated, although same source_id

    if source == 'mendeley':  # mendeley code doesn't yet send data to this function
        source_id = 1
    elif source == 'goodreads':
        source_id = 2
    else:
        source_id = 3  # native WYR docs, from native or api

    id = content.get('id')
    title = content.get('title')
    link = content.get('link')
    tags = content.get('tags')
    authors = content.get('authors')
    year = content.get('year')
    notes = content.get('notes')
    native_doc_id = content.get('native_doc_id')  # id from external sources

    if content.get('read') in [0, '0', 1, '1']:
        read = int(content.get('read'))
    else:
        read = 1  # default to read if value is anything else

    try:
        doc_to_edit = user.documents.filter_by(id=id).one()
    except NoResultFound:
        raise ex.NotUserDocException
    else:
        # add http:// if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        if source_id == 3 and link:
            doc = user.documents.filter(Documents.link==link).filter(Documents.source_id==source_id).filter(Documents.id!=id).first()

            if doc:
                raise ex.DuplicateLinkException(doc.id)
        
        if source in ['api', 'native'] and doc_to_edit.source_id != 3:
            raise ex.NotEditableDocException

        if not title:
            raise ex.NoTitleException(id)

        doc_to_edit.title = title
        doc_to_edit.link = link
        doc_to_edit.year = year
        doc_to_edit.notes = notes
        doc_to_edit.native_doc_id = native_doc_id

        # if changed from to-read to read, updated created, delete last_modified
        if doc_to_edit.read == 0 and read == 1:
            doc_to_edit.created = datetime.datetime.now(pytz.utc)
            doc_to_edit.last_modified = ''
        else:
            doc_to_edit.last_modified = datetime.datetime.now(pytz.utc)

        doc_to_edit.read = read

        if tags:
            add_or_update_tags(user, tags, doc_to_edit)
        else:
            # remove all tags if there were any
            if doc_to_edit.tags:
                doc_to_edit.tags.clear()

        if authors:
            add_or_update_authors(user, authors, doc_to_edit)
        else:
            # remove all authors if there were any
            if doc_to_edit.authors:
                doc_to_edit.authors.clear()

        db.session.commit()

        delete_orphaned_tags()
        delete_orphaned_authors()
        db.session.commit()

    return


def delete_item(id, user, source=''):
    '''Delete document.'''

    try:
        doc = user.documents.filter(Documents.id==id).one()
    except NoResultFound:
        raise ex.NotUserDocException
    else:
        if source in ['api', 'native'] and doc.source_id != 3:
            raise ex.NotDeleteableDocException
        
        user.documents.filter(Documents.id==id).delete()
        db.session.commit()

        delete_orphaned_tags()
        delete_orphaned_authors()
        db.session.commit()

    return


################
# MISC FUNCTIONS
################

def remove_to_read(source):
    ''' Delete to-read docs if user changes pref from including to excluding them. '''

    current_user.documents.filter(Documents.source_id==source, Documents.read==0).delete(synchronize_session='fetch')
    db.session.commit()

    if source == 1:
        flash("Any unread items from Mendeley have been removed.")
    if source == 2:
        flash("Any unread books from Goodreads have been removed.")

    return


def force_deauthorize(source):
    '''
    Manually deauthorize - or force deauthorization if source tokens are corrupted - and
    delete all documents associated with that source.
    '''

    if source not in ['Mendeley', 'Goodreads']:
        flash("Cannot deauthorize unknown source.")
        return

    if source == 'Mendeley':
        Documents.query.filter_by(user_id=current_user.id, source_id=1).delete()

        # delete source tokens
        SourceToken.query.filter_by(user_id=current_user.id, source_id=1).delete()

        # unset flags
        current_user.mendeley = 0
        current_user.mendeley_update = ''
        current_user.include_m_unread = 0
    if source == 'Goodreads':
        Documents.query.filter_by(user_id=current_user.id, source_id=2).delete()

        # delete source tokens
        SourceToken.query.filter_by(user_id=current_user.id, source_id=2).delete()

        # unset flags
        current_user.goodreads = 0
        current_user.goodreads_update = 'NULL'
        current_user.include_g_unread = 0

    db.session.commit()

    delete_orphaned_tags()
    delete_orphaned_authors()
    db.session.commit()

    return


def send_simple_message(to, subject, text):
    '''Send email via mailgun.'''
    mailgun = current_app.config['MAILGUN']

    return requests.post(
        mailgun['messages_url'],
        auth=('api', mailgun['api_key']),
        data={'from': mailgun['from'],
              'h:Reply-To': mailgun['reply_to'],
              'to': to,
              'subject': subject,
              'html': text})
