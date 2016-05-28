#see this for SQLAlchemy foreign keys: http://docs.sqlalchemy.org/en/latest/core/constraints.html

from app import db
from flask.ext.login import UserMixin

#main user table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True)
    password = db.Column(db.String(200))
    email = db.Column(db.String(100), unique=True)
    mendeley = db.Column(db.Integer)
    mendeley_update = db.Column(db.DateTime)
    goodreads = db.Column(db.Integer)
    goodreads_update = db.Column(db.DateTime)

#table of different services - manually add through mysql
class Services(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), unique=True)

#table for Tokens and Services by User
class Tokens(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'))
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    access_token = db.Column(db.String(200))
    refresh_token = db.Column(db.String(200))
    access_token_secret = db.Column(db.String(200))

###TABLES FOR DOCUMENT DATA#####################################################

#documents table
class Documents(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"))
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    title = db.Column(db.String(300))
    link = db.Column(db.String(300))
    created = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    read = db.Column(db.Integer)
    starred = db.Column(db.Integer)
    year = db.Column(db.String(4))
    note = db.Column(db.Text)
    native_doc_id = db.Column(db.String(50)) #need for Mendeley, maybe others

    #relationships
    tags = db.relationship('Tags', lazy="joined", backref="documents", cascade="all, delete-orphan")
    authors = db.relationship('Authors', lazy="joined", backref="documents", cascade="all, delete-orphan")
    file_links = db.relationship('FileLinks', lazy="joined", backref="documents", cascade="all, delete-orphan")


    def __init__(self, user_id, service_id, title):
        self.user_id = user_id
        self.service_id = service_id
        self.title = title

class Tags(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', onupdate="CASCADE", ondelete="CASCADE"))
    name = db.Column(db.String(100))

    def __init__(self, user_id, document_id, name):
        self.user_id = user_id
        self.document_id = document_id
        self.name = name

class Authors(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', onupdate="CASCADE", ondelete="CASCADE"))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role = db.Column(db.String(1), default=0)

    def __init__(self, user_id, document_id, first_name, last_name, role):
        self.user_id = user_id
        self.document_id = document_id
        self.first_name = first_name
        self.last_name = last_name
        self.role = role

class FileLinks(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', onupdate="CASCADE", ondelete="CASCADE"))
    file_link = db.Column(db.String(500))
    mime_type = db.Column(db.String(100))

    def __init__(self, document_id, file_link):
        self.document_id = document_id
        self.file_link = file_link





