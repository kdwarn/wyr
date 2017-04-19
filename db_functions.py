from app import db
from sqlalchemy import text
from flask.ext.login import current_user
from models import Tags, Authors, Documents

def get_user_tags():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's tags

    Returns list of dictionaries of user tags

    to-do: (possibly) - change to return list of Tag objects?
    '''
    sql = text('SELECT DISTINCT tags.name, tags.id from tags \
            JOIN document_tags ON (document_tags.tag_id = tags.id) \
            JOIN documents ON (documents.id = document_tags.document_id) \
            JOIN user ON (user.id = documents.user_id) \
            WHERE user.id = :x \
            ORDER BY tags.name');
    result = db.engine.execute(sql, x=current_user.id)
    tags = []
    for row in result:
        tags.append({'id': row[1], 'name': row[0]})
    return tags

def get_user_tag(tag_name):
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get one tag

    Returns Tag object
    '''
    sql = text('SELECT tags.id from tags \
            JOIN document_tags ON (document_tags.tag_id = tags.id) \
            JOIN documents ON (documents.id = document_tags.document_id) \
            JOIN user ON (user.id = documents.user_id) \
            WHERE user.id = :x AND tags.name = :y');
    result = db.engine.execute(sql, x=current_user.id, y=tag_name)
    row = result.fetchone()

    #row is a dict - now get the actual Tag object
    if row != None:
        to_read_tag = Tags.query.filter(Tags.id==row['id']).one()
        return to_read_tag
    else:
        return None

def get_user_tag_names():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's
    tag names

    Returns list of tag names
    '''
    sql = text('SELECT DISTINCT tags.name from tags \
            JOIN document_tags ON (document_tags.tag_id = tags.id) \
            JOIN documents ON (documents.id = document_tags.document_id) \
            JOIN user ON (user.id = documents.user_id) \
            WHERE user.id = :x \
            ORDER BY tags.name');
    result = db.engine.execute(sql, x=current_user.id)
    tags = []
    for row in result:
        tags.append(row[0])
    return tags

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

def get_user_authors():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's
    authors - id, first_name, last_name
    Returns a list of dictionaries
    '''
    sql = text('SELECT DISTINCT authors.id, authors.first_name, authors.last_name from authors \
            JOIN document_authors ON (document_authors.author_id = authors.id) \
            JOIN documents ON (documents.id = document_authors.document_id) \
            JOIN user ON (user.id = documents.user_id) \
            WHERE user.id = :x \
            ORDER BY authors.last_name');
    result = db.engine.execute(sql, x=current_user.id)
    authors = []
    for row in result:
        authors.append({'id': row[0], 'first_name': row[1], 'last_name': row[2]})
    return authors

def get_user_author_names():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's
    author names only
    '''
    sql = text('SELECT DISTINCT authors.first_name, authors.last_name from authors \
            JOIN document_authors ON (document_authors.author_id = authors.id) \
            JOIN documents ON (documents.id = document_authors.document_id) \
            JOIN user ON (user.id = documents.user_id) \
            WHERE user.id = :x \
            ORDER BY authors.last_name');
    result = db.engine.execute(sql, x=current_user.id)
    authors = []
    for row in result:
        authors.append(row[1] + ', ' + row[0])
    return authors

def str_authors_to_list(authors):
    ''' Input: string of (possibly comma- and semi-colon-separated) authors
        Output: list of dictionary of authors, stripped of empty authors and whitesapce
    '''

    #turn authors string into list
    #authors = authors.split(';')

    new_list_of_authors = []

    #now turn into list of dictionaries
    for author in authors[:].split(';'):
        # split on commas, at most once
        author = author.split(',', maxsplit=1)

        # author is now a list, w possibly 2 items. Turn into dict, and
        # strip whitespace, but only do if author[0] (last_name) is not empty
        if author[0].strip():
            try:
                author_dict = {'last_name':author[0].strip(),
                               'first_name':author[1].strip()}
            except IndexError:
                author_dict ={'last_name':author[0].strip()}

            #put that into new list
            new_list_of_authors.append(author_dict)

    return new_list_of_authors

def add_tags_to_doc(tags, doc):
    '''
    *tags* is a list of all tags (names) associated with this doc, from source
    *doc* is the database object
    '''

    #get user's existing tags to check if tags for this doc already exist
    user_tags = get_user_tags()

    # add user's existing tags (db object) to doc
    # if the user doesn't have existing tags, we don't won't need to do this
    if user_tags:
        #append any user's existing tags to the document, remove from list tags
        for user_tag in user_tags:
            for tag in tags[:]:
                if user_tag['name'] == tag:
                    #get the tag object and append to new_doc.tags
                    existing_tag = Tags.query.filter(Tags.id==user_tag['id']).one()
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
        # from tags so we don't try to add it again later.
        for tag in tags[:]:
            if tag in old_tags:
                tags.remove(tag)

    return doc, tags

def add_authors_to_doc(authors, doc):
    '''
    This does most of the work of adding authors to documents. Some additional
    work is done by remove_old_authors().

    *authors* is a list of all authors associated with this doc, from source
    *doc* is the database object
    '''

    #get user's existing authors to check if authors for this doc already exist
    user_authors = get_user_authors()

    #append any of user's exsting authors to document, remove from list authors
    for user_author in user_authors:
        for author in authors[:]:
            #if there's only one name, author[1] will through index error,
            #but must try to match both first_name and last_name first
            try:
                if (user_author['first_name'] == author['first_name']
                        and user_author['last_name'] == author['last_name']):
                    #get the author object and append to new_doc.authors
                    existing_author = Authors.query.filter(Authors.id==user_author['id']).one()
                    doc.authors.append(existing_author)
                    #now remove it, so we don't create a new author object below
                    authors.remove(author)
            except KeyError:
                if user_author['last_name'] == author['last_name']:
                    #get the author object and append to new_doc.authors
                    existing_author = Authors.query.filter(Authors.id==user_author['id']).one()
                    doc.authors.append(existing_author)
                    #now remove it, so we don't create a new author object below
                    authors.remove(author)

    #any author left in authors list will be a new one that needs to be created and appended to new_doc
    for author in authors:
        try:
            new_author = Authors(author['first_name'], author['last_name'])
        except KeyError:
            new_author = Authors(first_name='', last_name=author['last_name'])

        doc.authors.append(new_author)

    #remove orphaned authors
    #auto_delete_orphans(Documents.authors)

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
                if (author.first_name == old_author['first_name']
                        and author.last_name == old_author['last_name']):
                    doc.authors.remove(author)

    # both old authors and authors
    else:
        # Remove old authors user no longer wants associated with this doc
        for old_author in old_authors[:]:
            if old_author not in authors:
                for author in doc.authors[:]:
                    if (author.first_name == old_author['first_name']
                            and author.last_name == old_author['last_name']):
                        doc.authors.remove(author)

        #remove old_authors from authors - would be a duplicate
        for author in authors[:]:
            if author in old_authors:
                authors.remove(author)

    # to do: delete orphaned authors from db

    return doc, authors

# if user has changed pref from including to excluding to-read docs, del them
def remove_to_read(source):
    to_read_tag = get_user_tag('to-read')

    if to_read_tag != None:
        # delete all docs with to-read as tag
        current_user.documents.filter(Documents.source_id==source, Documents.tags.any(name=to_read_tag.name)).delete(synchronize_session='fetch')

        db.session.commit()
    return