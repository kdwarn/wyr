from app import db
from sqlalchemy import text
from flask.ext.login import current_user

def get_user_tags():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's
    tags - id and name
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

def get_user_tag_names():
    '''
    Use sql (can't figure out how to get SQLAlchemy to do this) to get user's
    tag names only
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

    #turn string into tags into list
    tags = tags.split(',')
    #strip whitespace
    i = 0
    for tag in tags[:]:
        tags[i] = tags[i].strip()
        i += 1

    #delete empty tags
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
        Output: list of list of authors, stripped of empty authors and whitesapce
    '''

    #turn authors string into list
    authors = authors.split(';')

    #delete any empty items
    for author in authors[:]:
        if not author.strip():
            authors.remove(author)

    #now turn into list of lists
    i=0
    for author in authors[:]:
        authors[i] = author.split(',')
        i += 1

    #now strip white space and replace any empty name with None
    for author in authors:
        i = 0
        for name in author:
            author[i] = author[i].strip()
            if not name.strip():
                author[i] = ''
            i += 1

    #it's still possible that there's an empty author set or set with only first name
    for author in authors:
        if not author[0]:
            authors.remove(author)

    return authors