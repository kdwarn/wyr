from collections import namedtuple
import datetime

from flask import flash, current_app
from flask_login import current_user
import pytz
import requests
import stripe

from app import db
from .models import Tags, Authors, Documents, Tokens, document_tags, document_authors
from . import exceptions as ex


##########################
# TAG AND AUTHOR FUNCTIONS
##########################

def get_user_tags(user):
    '''Gets user's tags, as objects, in alphabeticcal order by tag.name.'''

    tags = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id).order_by(Tags.name).all()

    return tags


def get_user_tag(user, tag_name):
    '''Get one tag object.'''

    tag = Tags.query.join(document_tags).join(Documents).filter(Documents.user_id==user.id, Tags.name==tag_name).first()

    return tag


def str_tags_to_list(tags):
    ''' Input: string of (possibly comma-separated) tags
        Output: list of tags, stripped of empty tags and whitesapce
    '''

    # turn string of tags into list
    tags = tags.split(',')

    # strip whitespace
    for i in range(len(tags[:])):
        tags[i] = tags[i].strip()

    # delete empty tags
    for tag in tags[:]:
        if not tag:
            tags.remove(tag)

    return tags


def add_tags_to_doc(user, tags, doc):
    '''
    *tags* is a list of all tags (names) associated with this doc, from source
    *doc* is the database object
    '''

    #get user's existing tags to check if tags for this doc already exist
    user_tags = get_user_tags(user)

    # add user's existing tags (db object) to doc
    # if the user doesn't have existing tags, we don't won't need to do this
    if user_tags:
        #append any user's existing tags to the document, remove from list tags
        for user_tag in user_tags:
            for tag in tags[:]:
                # strip both of any non-alphanumeric characters, make them
                # lower case, and check against each other.
                # This avoids creating what are essentially duplicate tags.
                if (''.join(ch for ch in tag.lower() if ch.isalnum())
                    == ''.join(ch for ch in user_tag.name.lower() if ch.isalnum())):
                    #get the tag object and append to new_doc.tags
                    existing_tag = Tags.query.filter(Tags.id==user_tag.id).one()
                    doc.tags.append(existing_tag)
                    #now remove it, so we don't create a new tag object below
                    tags.remove(tag)

    #any tag left in tags list will be a new one that needs to be created
    #create new tag objects for new tags, append to the doc
    for tag in tags:
        new_tag = Tags(tag)
        doc.tags.append(new_tag)

    #remove orphaned tags
    #auto_delete_orphans(Documents.tags)

    return doc

def remove_old_tags(old_tags, tags, doc):
    '''
    remove tags previously associated with doc from doc

    *old tags* is list of old tags (names)
    *tags* is list of tags (names)
    *doc* is doc object
    '''

    # if no tags (user removed all tags from doc), just remove old tags
    if not tags:
        for old_tag in old_tags[:]:
            #to get the right tag to remove, loop through all and match by name
            for tag in doc.tags[:]:
                if tag.name == old_tag:
                    doc.tags.remove(tag)

    # both old tags and new tags.
    else:
        # Remove old tags user no longer wants associated with this doc.
        for old_tag in old_tags[:]:
            if old_tag not in tags:
                #to get the right tag to remove, loop through all and match by name
                for tag in doc.tags[:]:
                    if tag.name == old_tag:
                        doc.tags.remove(tag)

        # If tag was in old_tags, it's already associated with doc. So remove
        # from tags list so we don't try to add it again later.
        for tag in tags[:]:
            if tag in old_tags:
                tags.remove(tag)

    return doc, tags


def get_user_authors(user):
    '''Get user's authors.'''

    authors = Authors.query.join(document_authors).join(Documents).filter(Documents.user_id==user.id).order_by(Authors.last_name).all()

    return authors


def str_authors_to_namedtuple(authors):
    ''' Input: string of (possibly comma- and semi-colon-separated) authors
        Output: list of namedtuples, stripped of empty authors and whitesapce
    '''

    Authors_nt = namedtuple('Authors_nt', ['first_name', 'last_name'])

    list_of_authors = []

    #now turn into list of dictionaries
    for author in authors[:].split(';'):
        # split on commas, at most once
        author = author.split(',', maxsplit=1)

        # author is now a list, w possibly 2 items. Turn into named_tuple, and
        # strip whitespace, but only do if author[0] (last_name) is not empty
        if author[0].strip():
            try:
                a = Authors_nt(author[1].strip(), author[0].strip())
            except IndexError: # only one name
                a = Authors_nt('', author[0].strip())

            list_of_authors.append(a)

    return list_of_authors


def add_authors_to_doc(user, authors, doc):
    '''
    This does most of the work of adding authors to documents. Some additional
    work is done by remove_old_authors().

    *authors* is a list of all authors associated with this doc, from source
    *doc* is the database object
    '''

    # get user's existing authors to check if authors for this doc already exist
    user_authors = get_user_authors(user)

    # append any of user's exsting authors to document, remove from list authors
    if user_authors:
        for user_author in user_authors:
            for author in authors[:]:
                # if there's only one name, author.first_name will throw index error,
                # but must try to match both first_name and last_name first
                try:
                    if (user_author.first_name == author.first_name
                            and user_author.last_name == author.last_name):
                        #get the author object and append to new_doc.authors
                        existing_author = Authors.query.filter(Authors.id==user_author.id).one()
                        doc.authors.append(existing_author)
                        #now remove it, so we don't create a new author object below
                        authors.remove(author)
                except KeyError:
                    if user_author.last_name == author.last_name:
                        #get the author object and append to new_doc.authors
                        existing_author = Authors.query.filter(Authors.id==user_author.id).one()
                        doc.authors.append(existing_author)
                        #now remove it, so we don't create a new author object below
                        authors.remove(author)

    # any author left in authors list will be a new one that needs to be created and appended to new_doc
    for author in authors:
        try:
            new_author = Authors(author.first_name, author.last_name)
        except KeyError:
            new_author = Authors('', author.last_name)

        doc.authors.append(new_author)

    return doc

def remove_old_authors(old_authors, authors, doc):
    '''
    remove authors no longer associated with doc from it

    *authors* is list of author dicts
    *old_authors* is list of old author dicts
    *doc* is doc object
    '''

    # if no authors (user removed all authors from doc), just remove old authors
    if not authors:
        for old_author in old_authors[:]:
            #to get the right author to remove, loop and match by name
            for author in doc.authors[:]:
                if (author.first_name == old_author.first_name
                        and author.last_name == old_author.last_name):
                    doc.authors.remove(author)

    # both old authors and authors
    else:
        # Remove old authors user no longer wants associated with this doc
        for old_author in old_authors[:]:
            if old_author not in authors:
                for author in doc.authors[:]:
                    if (author.first_name == old_author.first_name
                            and author.last_name == old_author.last_name):
                        doc.authors.remove(author)

        #remove old_authors from authors - would be a duplicate
        for author in authors[:]:
            if author in old_authors:
                authors.remove(author)


    return doc, authors


def add_item(content, user):
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
        tags = str_tags_to_list(tags)
        doc = add_tags_to_doc(user, tags, doc)

    if authors:
        authors = str_authors_to_namedtuple(authors)
        doc = add_authors_to_doc(user, authors, doc)

    user.documents.append(doc)

    db.session.commit()

    return


def edit_item(content, user):
    '''Edit existing document.'''

    id = content.get('id')
    title = content.get('title')
    link = content.get('link')
    tags = content.get('tags')
    old_tags = content.get('old_tags')
    authors = content.get('authors')
    old_authors = content.get('old_authors')
    year = content.get('year')
    notes = content.get('notes')
    read = int(content.get('read')) if content.get('read') else 1 # default to read

    if not title:
        raise ex.NoTitleException(id)

    if read not in [0,1]:
        raise ex.BadReadValueError

    doc_to_edit = user.documents.filter(Documents.source_id==3, Documents.id==id).first()

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

    # update tags
    # if there were old tags, remove those no longer associated with doc,
    # update the doc and also return updated list of tags
    old_tags = str_tags_to_list(old_tags)
    tags = str_tags_to_list(tags)

    if old_tags:
        doc_to_edit, tags = remove_old_tags(old_tags, tags, doc_to_edit)

    # add any new tags to doc
    if tags:
        doc_to_edit = add_tags_to_doc(user, tags, doc_to_edit)

    # update authers in same manner
    old_authors = str_authors_to_namedtuple(old_authors)
    authors = str_authors_to_namedtuple(authors)

    if old_authors:
        doc_to_edit, authors = remove_old_authors(old_authors, authors, doc_to_edit)

    if authors:
        doc_to_edit = add_authors_to_doc(user, authors, doc_to_edit)

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
