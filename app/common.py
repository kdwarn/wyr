from collections import namedtuple
import datetime

from flask import flash, current_app
from flask_login import current_user
import pytz
import requests
from sqlalchemy.orm.exc import NoResultFound
import stripe

from app import db
from .models import Tags, Authors, Documents, Tokens, document_tags, document_authors
from . import exceptions as ex


###############
# TAG FUNCTIONS
###############

def get_user_tags(user):
    '''Gets user's tags, as objects, in alphabeticcal order by tag.name.'''

    tags = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id).order_by(Tags.name).all()

    return tags


def get_user_tag(user, tag_name):
    '''Get one tag object.'''

    # TODO: change to one(), put in try/except block

    tag = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id, Tags.name==tag_name).first()

    return tag


def str_tags_to_list(tags):
    ''' Input: string of (possibly comma-separated) tags
        Output: list of tags, stripped of empty tags and whitesapce
    '''

    # turn string of tags into list
    tags = tags.split(',')

    # strip whitespace
    tags = [tag.strip() for tag in tags]

    # delete empty tags
    for tag in tags[:]:
        if not tag:
            tags.remove(tag)

    return tags


def remove_all_tags(doc):
    '''Remove all tags associated with a document.'''
    for tag in doc.tags[:]:
        doc.tags.remove(tag)


def add_or_update_tags(user, tags, doc):

    submitted_tags = [tag.strip() for tag in tags]  # names

    doc_tag_names = [tag.name for tag in doc.tags]

    # get all of the user's existing tags
    user_tags = get_user_tags(user)

    user_tag_names = [tag.name for tag in user_tags]

    # remove any tags associated with this doc if not in new tags submitted with edit
    if doc.tags:
        for associated_tag in doc.tags[:]:
            if associated_tag.name not in submitted_tags:
                doc.tags.remove(associated_tag)

    for submitted_tag in submitted_tags[:]:
        # only do this if not already associated with doc
        if submitted_tag not in doc_tag_names:

            # not doing the duplicate check - could actually be a worse
            # error if removing space from a tag results in a completely
            # different tag/word

            # check if user already uses this tag in another doc
            if submitted_tag in user_tag_names:
                # associate that user tag to this doc
                existing_tag = get_user_tag(user, submitted_tag)
                doc.tags.append(existing_tag)
                # now remove from list, so we don't create a new tag object below
                submitted_tags.remove(submitted_tag)
            else:
                # create a new tag and associate it to the doc
                new_tag = Tags(submitted_tag)
                doc.tags.append(new_tag)

    return


def delete_orphaned_tags(user, tag):

    tags = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id, Tags.id==tag.id).all()

    # if no tags, user has no other documents tagged with this tag, so safe to delete
    if not tags:
        Tags.query.filter(Tags.id==tag.id).delete()

    return


##################
# AUTHOR FUNCTIONS
##################

Authors_nt = namedtuple('Authors_nt', ['last_name', 'first_name'])


def get_user_authors(user):
    '''Get user's authors.'''

    authors = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id).order_by(Authors.last_name).all()

    return authors


def get_user_author(user, first_name, last_name):
    '''Get one of the user's authors.'''

    # TODO: put in try/except block

    authors = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id, \
                Authors.first_name==first_name, Authors.last_name==last_name).one()

    return authors


def str_authors_to_namedtuple(authors):
    ''' Input: string of (possibly comma- and semi-colon-separated) authors
        Output: list of namedtuples, stripped of empty authors and whitesapce
    '''

    Authors_nt = namedtuple('Authors_nt', ['first_name', 'last_name'])

    list_of_authors = []

    for author in authors[:].split(';'):
        author = author.split(',', maxsplit=1)

        # TODO: does author[0] still exist if no commas in string?

        if author[0].strip():
            try:
                a = Authors_nt(author[1].strip(), author[0].strip())
            except IndexError: # only one name
                a = Authors_nt('', author[0].strip())

            list_of_authors.append(a)

    return list_of_authors


def list_authors_to_namedtuple(authors):
    ''' Input: list of (possibly comma-separated) authors
        Output: list of namedtuples, stripped of empty authors and whitesapce
    '''
    authors_as_nt = []

    for author in authors[:]:
        author_names = author.split(',', maxsplit=1)

        try:
            if author_names[0].strip():
                # if last name is not empty, try to use both last name and first name
                a = (author_names[0].strip(), author_names[1].strip())
            else:
                # try to just use the first name as the last name
                a = (author_names[1].strip(), '')
        except IndexError: # only one name
            try:
                a = (author_names[0].strip(), '')
            except IndexError:
                a = (author_names[1].strip(), '')

        authors_as_nt.append(Authors_nt(*a))

    return authors_as_nt


def remove_all_authors(doc):
    for author in doc.authors[:]:
        doc.authors.remove(author)


def add_or_update_authors(user, authors, doc):
    '''Add authors to doc or update authors associated with doc.

    Input: **authors** is list of authors as namedtuple
    Output: none, doc is updated.
    '''

    # whitespace has already been stripped

    submitted_authors = [Authors_nt(author.last_name, author.first_name) for author in authors]

    if doc.authors:
        associated_authors = [Authors_nt(author.last_name, author.first_name) for author in doc.authors]

    # get all of the user's existing authors
    user_authors = get_user_authors(user)

    if user_authors:
        user_authors = [Authors_nt(author.last_name, author.first_name) for author in user_authors]

    # remove any authors associated with this doc if not in new authors submitted with edit
    if doc.authors:
        for author in associated_authors:
            if author not in submitted_authors:
                author_to_remove = get_user_author(user, author.first_name, author.last_name)
                doc.authors.remove(author_to_remove)

    # add any new authors to this doc
    for author in submitted_authors:
        if author in user_authors:
            # associate any authors user already has
            author_to_associate = get_user_author(user, author.first_name, author.last_name)
            doc.authors.append(author_to_associate)
        else:
            # create a new author for this user
            new_author = Authors(author.first_name.strip(), author.last_name.strip())
            doc.authors.append(new_author)

    return


def delete_orphaned_authors(user, author):

    authors = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id, Authors.id==author.id).all()

    # if no authors returned, user has no other documents by this author,
    # so safe to delete
    if not authors:
        Authors.query.filter(Authors.id==author.id).delete()

    return


#############################
# ADD, EDIT, AND DELETE ITEMS
#############################

def add_item(content, user, caller=''):
    '''Add document to database.'''

    title = content.get('title')
    link = content.get('link')
    tags = content.get('tags')
    authors = content.get('authors')
    year = content.get('year')
    notes = content.get('notes')
    read = int(content.get('read')) if content.get('read') else 1 # default to read

    if not title:
        raise ex.NoTitleException

    if link:
        # add "http://" if not there or else will be relative link within site
        if 'http://' not in link and 'https://' not in link:
            link = 'http://' + link

        doc = user.documents.filter_by(link=link, source_id=3).first()

        if doc:
            raise ex.DuplicateLinkException(doc.id)

    if read not in [0,1]:
        raise ex.BadReadValueError

    doc = Documents(user.id, 3, title, link=link, year=year, note=notes, read=read,
                    created=datetime.datetime.now(pytz.utc))

    if tags:
        if caller == 'native':
            tags = str_tags_to_list(tags)
        add_or_update_tags(user, tags, doc)

    if authors:
        if caller == 'native':
            authors = str_authors_to_namedtuple(authors)

        authors = list_authors_to_namedtuple(authors)
        add_or_update_authors(user, authors, doc)

    user.documents.append(doc)

    db.session.commit()

    return


def edit_item(content, user, caller=''):
    '''Edit existing document.'''

    id = content.get('id')
    title = content.get('title')
    link = content.get('link')
    tags = content.get('tags')
    authors = content.get('authors')
    year = content.get('year')
    notes = content.get('notes')
    read = int(content.get('read')) if content.get('read') else 1 # default to read

    if not title:
        raise ex.NoTitleException(id)

    if read not in [0,1]:
        raise ex.BadReadValueError

    try:
        doc_to_edit = user.documents.filter(Documents.source_id==3, Documents.id==id).one()
    except NoResultFound:
        raise ex.NotUserDocException
    else:
        # add http:// if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        doc_to_edit.title = title
        doc_to_edit.link = link
        doc_to_edit.year = year
        doc_to_edit.note = notes
        doc_to_edit.read = read

        # if changed from to-read to read, updated created, delete last_modified
        if doc_to_edit.read == 0 and read == '1':
            doc_to_edit.created = datetime.datetime.now(pytz.utc)
            doc_to_edit.last_modified = ''
        else:
            doc_to_edit.last_modified = datetime.datetime.now(pytz.utc)

        if tags:
            # if called by native.py, need to convert string of tags to list
            if caller == 'native':
                tags = str_tags_to_list(tags)

            add_or_update_tags(user, tags, doc_to_edit)
        else:
            # remove all tags if there were any
            if doc_to_edit.tags:
                remove_all_tags(doc_to_edit)

        if authors:
            if caller == 'native':
                authors = str_authors_to_namedtuple(authors)
            else:
                authors = list_authors_to_namedtuple(authors)

            authors = add_or_update_authors(user, authors, doc_to_edit)
        else:
            # remove all authors if there were any
            if doc_to_edit.authors:
                remove_all_authors(doc_to_edit)

        db.session.commit()

    return


def delete_item(id, user):
    '''Delete document.'''

    try:
        # verify doc trying to be deleted is the user's
        doc = user.documents.filter(Documents.id==id, Documents.source_id==3).one()
    except NoResultFound:
        raise ex.NotUserDocException
    else:
        # delete doc tags
        if doc.tags:
            for tag in doc.tags[:]:
                doc.tags.remove(tag)
                delete_orphaned_tags(user, tag)


        # delete doc authors
        if doc.authors:
            for author in doc.authors[:]:
                doc.authors.remove(author)
                delete_orphaned_authors(user, author)

        # delete it
        doc = user.documents.filter(Documents.id==id, Documents.source_id==3).delete()

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
    If authorization becomes corrupted somehow, deauthorize a source directly
    and delete all documents from it.
    '''

    if source not in ['Mendeley', 'Goodreads']:
        flash("Cannot deauthorize unknown source.")
        return

    if source == 'Mendeley':
        #delete documents
        Documents.query.filter_by(user_id=current_user.id, source_id=1).delete()
        #delete tokens
        Tokens.query.filter_by(user_id=current_user.id, source_id=1).delete()
        #unset flags
        current_user.mendeley = 0
        current_user.mendeley_update = ''
        current_user.include_m_unread = 0
    if source == 'Goodreads':
        #delete documents
        Documents.query.filter_by(user_id=current_user.id, source_id=2).delete()
        #delete tokens
        Tokens.query.filter_by(user_id=current_user.id, source_id=2).delete()
        #unset flags
        current_user.goodreads = 0
        current_user.goodreads_update = 'NULL'
        current_user.include_g_unread = 0

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


def get_stripe_info():
    '''Get user's Stripe info.'''
    if current_user.stripe_id is not None:
        donor = stripe.Customer.retrieve(current_user.stripe_id)

        #simplify object a bit, see if user has current subscription to plan
        try:
            subscription = donor.subscriptions['data'][0]
        except IndexError:
            subscription = ''

        #drop everything else from donor
        #to do

    else:
        donor = ''
        subscription = ''

    return donor, subscription
