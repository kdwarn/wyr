from flask_login import UserMixin

from app import db, login


# association tables
# see for many-to-many tags-documents relationship
# http://flask-sqlalchemy.pocoo.org/2.1/models/
# and http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
document_tags = db.Table('document_tags',
                         db.Column('document_id',
                                   db.Integer,
                                   db.ForeignKey('documents.id', ondelete='CASCADE'),
                                   primary_key=True),
                         db.Column('tag_id',
                                   db.Integer,
                                   db.ForeignKey('tags.id', ondelete='CASCADE'),
                                   primary_key=True)
                        )


document_authors = db.Table('document_authors',
                        db.Column('author_id', db.ForeignKey('authors.id'), primary_key=True),
                        db.Column('document_id', db.ForeignKey('documents.id'), primary_key=True))

bunch_tags = db.Table('bunch_tags',
                      db.Column('bunch_id',
                                db.Integer,
                                db.ForeignKey('bunches.id'),
                                primary_key=True),
                      db.Column('tag_id',
                                db.Integer,
                                db.ForeignKey('tags.id'),
                                primary_key=True)
                     )

# main user table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    salt = db.Column(db.String(32))  # used for generating JSON Web Token (jwt) in API
    email = db.Column(db.String(100), unique=True)
    mendeley = db.Column(db.Integer)
    mendeley_update = db.Column(db.DateTime)
    goodreads = db.Column(db.Integer)
    goodreads_update = db.Column(db.DateTime)
    stripe_id = db.Column(db.String(50))
    home_page = db.Column(db.Integer)
    include_m_unread = db.Column(db.Integer)
    include_g_unread = db.Column(db.Integer)
    auto_close = db.Column(db.Integer)
    markdown = db.Column(db.Integer)

    # relationships
    documents = db.relationship('Documents',
                                lazy='dynamic',
                                backref=db.backref('user', cascade='all, delete')
                               )

    def __init__(self, username, password, salt, email):
        self.username = username
        self.password = password
        self.salt = salt
        self.email = email
        self.include_m_unread = 0
        self.include_g_unread = 0
        self.auto_close = 0
        self.markdown = 1

@login.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id)
    if user.count() == 1:
        return user.one()
    return None


#############################
# SOURCES AND SOURCE TOKENS #
#############################

class Sources(db.Model):
    '''
    Source of documents. Can be:
        1 - Mendeley
        2 - Goodreads
        3 - Native
    '''
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), unique=True)


class Tokens(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE')
                        )
    source_id = db.Column(db.Integer, db.ForeignKey('sources.id'))
    access_token = db.Column(db.String(200))
    refresh_token = db.Column(db.String(200))
    access_token_secret = db.Column(db.String(200))


#################
# DOCUMENT DATA #
#################

class Documents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE")
                       )  # can/should the onupdate can be deleted?
    source_id = db.Column(db.Integer, db.ForeignKey('sources.id'))
    title = db.Column(db.String(300))
    link = db.Column(db.String(300))
    created = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    read = db.Column(db.Integer)
    starred = db.Column(db.Integer)
    year = db.Column(db.String(4))
    note = db.Column(db.Text)
    native_doc_id = db.Column(db.String(50))  # needed for Mendeley and Goodreads

    # relationships
    tags = db.relationship('Tags',
                           secondary=document_tags,
                           lazy='joined',
                           backref=db.backref('documents', cascade='all, delete')
                          )
    authors = db.relationship('Authors',
                              secondary=document_authors,
                              lazy='joined',
                              backref=db.backref('documents', cascade='all, delete')
                             )
    file_links = db.relationship('FileLinks',
                                 lazy="joined",
                                 backref="documents",
                                 cascade="all, delete, delete-orphan"
                                )

    def __init__(self, user_id, source_id, title, link='', created='', read='', year='', note=''):
        self.user_id = user_id
        self.source_id = source_id
        self.title = title
        self.link = link
        self.created = created
        self.read = read
        self.year = year
        self.note = note


class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    def __init__(self, name):
        self.name = name


class Authors(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))

    def __init__(self, first_name, last_name):
        self.first_name = first_name
        self.last_name = last_name


class FileLinks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer,
                            db.ForeignKey('documents.id', onupdate="CASCADE", ondelete="CASCADE")
                           )
    file_link = db.Column(db.String(500))
    mime_type = db.Column(db.String(100))

    def __init__(self, document_id, file_link):
        self.document_id = document_id
        self.file_link = file_link


class Bunches(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE")
                       )
    selector = db.Column(db.String(4))  # "and" or "or"
    name = db.Column(db.String(100))

    # relationships
    tags = db.relationship('Tags',
                           secondary=bunch_tags,
                           lazy='joined',
                           backref=db.backref('bunches', cascade='all, delete')
                          )

    def __init__(self, user_id, selector, name):
        self.user_id = user_id
        self.selector = selector
        self.name = name
