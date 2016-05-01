from flask import Flask, render_template, request, session, redirect, url_for, \
    abort, flash, jsonify
from flask.ext.login import LoginManager, login_user, logout_user, \
    login_required, current_user
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from requests_oauthlib import OAuth2Session, OAuth1Session
from xml.etree import ElementTree
from time import time
from config import m, g
from passlib.context import CryptContext
from datetime import datetime, timedelta
from flask.ext.mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from random import random
from math import ceil

#from testing import test_doc, test_tag, test_author

app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)

from models import User, Tokens, Documents, Tags, Authors, FileLinks

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# use when restructuring database - first drop tables manually through mysql console
@app.before_first_request
def init_request():
    db.create_all()
    db.session.commit()

#csrf protection from http://flask.pocoo.org/snippets/3/
#(must use  <input name="_csrf_token" type="hidden" value="{{ csrf_token() }}"> in template forms
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or "{}".format(token) != request.form.get('_csrf_token'):
            return redirect(url_for('index'))

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = random()
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
#end csrf protection

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id)
    if user.count() == 1:
        return user.one()
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        #code to fetch and manipulate read items from various services
        user = User.query.get(current_user.id)
        #first, update any docs if last update more than 3 hours ago
        then = datetime.now() - timedelta(hours=3)
        if user.mendeley == 1 and current_user.mendeley_update < then:
            update_mendeley()
        if user.goodreads == 1 and current_user.goodreads_update < then:
            update_goodreads()

        #this is this easy b/c I set up sqlalchemy relationships in models.py
        docs = Documents.query.filter_by(user_id=current_user.id).order_by(desc(Documents.created)).all()

        if not docs:
            flash('You don\'t appear to have any read documents yet. You can add items \
            individually or authorize services below.')
            return redirect(url_for('settings'))

        return render_template('read.html', docs=docs)
    else:
        return render_template('index.html')

@app.route('/contact', methods = ['GET', 'POST'])
def contact():
    if request.method == 'GET':
        return render_template('contact.html')
    elif request.method == 'POST':

        if current_user.is_authenticated:
            name = current_user.username
            email = current_user.email
        else:
            email = request.form['email']
            name = request.form['name']

        comments = request.form['comments']
        comments = name + ' (' + email + ') said: ' + comments
        mail = Mail(app)
        msg = Message('Comments on WYR from ' + name + ' (' + email + ')', sender='whatyouveread@gmail.com', recipients=['whatyouveread@gmail.com'])
        msg.body = comments
        mail.send(msg)
        flash("Your comments have been sent. Thank you.")

    return redirect(url_for('index'))

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        username = request.form['wyr_username']
        email = request.form['email']
        password = request.form['wyr_password']
        confirm_password = request.form['wyr_confirm']

        #checks
        error = 0
        if User.query.filter_by(username=username).count() > 0:
            error = 1
            flash('Sorry, username {} is already taken.'.format(username))
        if User.query.filter_by(email=email).count() > 0:
            error = 1
            flash('Sorry, the email address {} is already in use.'.format(email))
        if password != confirm_password:
            error = 1
            flash('Your passwords did not match. Please try again.')
        if len(password) < 5:
            error = 1
            flash('Your password is too short. Please try again.')
        if '@' not in email:
            error = 1
            flash('The email you entered does not appear to be valid.')

        if error == 1:
            return redirect(url_for('sign_up'))

        #use passlib to encrypt padd()assword
        myctx = CryptContext(schemes=['pbkdf2_sha256'])
        hash = myctx.encrypt(password)

        user = User(username=username, password=hash)
        db.session.add(user)
        db.session.commit()

        #generate the token, send the email, then return user to login
        action = 'confirm' #used to differentiate between confirming and changing email in confirm()
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email_hash = serializer.dumps([user.id, email, action], salt='email')
        mail = Mail(app)
        msg = Message('Confirm your email address', sender='whatyouveread@gmail.com', recipients=[email])
        msg.body = 'Welcome to What You\'ve Read. Please confirm your email by clicking on this link: \
        http://www.whatyouveread.com/confirm/{}'.format(email_hash)
        mail.send(msg)

        flash('You\'ve registered the username {}. Please check your email and follow the link provided to confirm your address.'.format(username))
        return redirect(url_for('index'))
    else:
        abort(405)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('index.html', next=request.args.get('next'))
    elif request.method == 'POST':
        username = request.form['wyr_username']
        password = request.form['wyr_password']
        remember = request.form.getlist('remember')

        #first see if username exists
        if User.query.filter_by(username=username).count() == 1:
            #get their encrypted pass and check it
            user = User.query.filter_by(username=username).first()

            myctx = CryptContext(schemes=['pbkdf2_sha256'])
            if myctx.verify(password, user.password) == True:
                if remember:
                    login_user(user, remember=True)
                else:
                    login_user(user)

                flash('Welcome back, {}.'.format(username))

                try:
                    next = request.form['next']
                    return redirect(next)
                except:
                    return redirect(url_for('index'))
            else:
                flash('Sorry, the password is incorrect.')
                return redirect(url_for('index'))
        else:
            flash('Username does not exist.')
            return redirect(url_for('index'))
    else:
        return abort(405)

@app.route('/logout')
def logout():
    logout_user()
    flash('You\'ve been logged out.')
    return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template('change_password.html')
    elif request.method == 'POST':
        current_password = request.form['wyr_current_password']
        new_password = request.form['wyr_new_password']
        confirm_password = request.form['wyr_confirm_password']

        #first verify current password
        myctx = CryptContext(schemes=['pbkdf2_sha256'])
        if myctx.verify(current_password, current_user.password) == True:
            #password checks
            if len(new_password) < 5:
                flash('Password is too short. Please try again.')
                return redirect(url_for('change_password'))
            elif new_password != confirm_password:
                flash('The confirmation password did not match the new password you entered.')
                return redirect(url_for('change_password'))
            else:
                #use passlib to encrypt password
                myctx = CryptContext(schemes=['pbkdf2_sha256'])
                hash = myctx.encrypt(new_password)

                current_user.password = hash
                db.session.commit()

                flash('Your password has been updated.')
                return redirect(url_for('settings'))
        else:
            flash('Password is incorrect.')
            return redirect(url_for('change_password'))
    else:
        return abort(405)

#display form to send email link to reset password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')
    elif request.method == 'POST':
        if request.form['send_email'] == "Cancel":
            return redirect(url_for('index'))

        email = request.form['email']

        #check we have the email
        if User.query.filter_by(email=email).count() > 0:
            #generate the token, send the email, then return user to login
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([email], salt='email')
            mail = Mail(app)
            msg = Message('Reset password', sender='whatyouveread@gmail.com', recipients=[email])
            msg.body = 'To reset your password, please follow this link: \
            http://www.whatyouveread.com/reset_password/{}'.format(email_hash)
            mail.send(msg)
            flash('An email has been sent to you. Please follow the link provided to reset your password.')
            return redirect(url_for('index'))
        else:
            flash('No account with that email exists.')
            return redirect(url_for('index'))
    else:
        return abort(405)

@app.route('/reset_password/<hash>', methods=['GET', 'POST'])
def reset_password(hash, expiration=3600):
    if request.method == 'GET':
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            decoded = serializer.loads(hash, salt='email', max_age=expiration)
        except:
            return False ### need to see what this returns and probably make more user friendly#############################################################################

        user = User.query.filter_by(email=decoded[0])
        if user.count() > 0:
            return render_template('reset_password.html', hash=hash)
        else:
            return abort(405)
    elif request.method == 'POST':
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            decoded = serializer.loads(hash, salt='email', max_age=expiration)
        except:
            return False ### need to see what this returns and probably make more user friendly#############################################################################

        #get user's id to update password
        user = User.query.filter_by(email=decoded[0]).first()

        if user:
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            #password checks ############################ COULD TURN THIS INTO A FUNCITON #####################################
            if len(password) < 5:
                flash('Password is too short. Please try again.')
                return redirect(url_for('reset_password'))
            elif password != confirm_password:
                flash('The confirmation password did not match the new password you entered.')
                return redirect(url_for('reset_password'))
            else:
                #use passlib to encrypt password
                myctx = CryptContext(schemes=['pbkdf2_sha256'])
                hash = myctx.encrypt(password)
                user.password = hash
                db.session.commit()

                flash('Your password has been updated. Please use it to login.')
                return redirect(url_for('login'))
        else:
            flash('Could not find an account associated with that email address.')
            return redirect(url_for('forgot_password'))
    else:
        return abort(405)

# change user email (in confunction with confirm())
@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'GET':
        step = request.args.get('step')
        hash = request.args.get('hash')
        return render_template('change_email.html', step=step, hash=hash)
    elif request.method == 'POST':
        #email user to confirm they one who initiated email change
        if 'step1' in request.form:
            if request.form['step1'] == "Cancel":
                return redirect(url_for('settings'))

            action = 'change' #used to differentiate between confirming and changing email in confirm()
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([current_user.id, current_user.email, action], salt='email')
            mail = Mail(app)
            msg = Message('Confirm request to change email', sender='whatyouveread@gmail.com', recipients=[current_user.email])
            msg.body = 'What You\'ve Read has received a request to change your email address. Please follow this link to confirm this \
            was you: http://www.whatyouveread.com/confirm/{}'.format(email_hash)
            mail.send(msg)

            flash('Please check your email and follow the link provided to confirm your current email address. You will then \
            be able to enter a new email address (which you will also have to verify.)')
            return redirect(url_for('settings'))

        #get user's new email address, send another confirmation to that one
        if 'step2' in request.form:
            if request.form['step2'] == "Cancel":
                return redirect(url_for('settings'))

            hash = request.form['hash']
            new_email = request.form['new_email']
            current_password = request.form['wyr_current_password']

            #check hash
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            try:
                serializer.loads(hash, salt='email', max_age=3600)
            except SignatureExpired:
                flash('The link has expired. If you still want to change your email address, you must re-start the process.')
                return redirect(url_for('settings'))
            except: #fix elsewhere.
                return "Error confirming your credentials." ### need to see what this returns and probably make more user friendly#############################################################################

            #verify password
            myctx = CryptContext(schemes=['pbkdf2_sha256'])
            if myctx.verify(current_password, current_user.password) != True:
                flash('Password is incorrect. Please hit back in your browser and refresh the page to try again.')
                return redirect(url_for('settings'))

            #minimum check that it's an email:
            if '@' not in new_email:
                flash('That doesn\'t look like an email address.  Please hit back in your browser and refresh the page to try again.')
                return redirect(url_for('settings'))

            #check if email already in use in another account
            if User.query.filter_by(email=new_email).count() > 0:
                flash('Sorry, that email address is already in use.  Please hit back in your browser and refresh the page to try again.')
                return redirect(url_for('settings'))

            #send verification email to new email address
            action = 'confirm' #used to differentiate between confirming and changing email in confirm()
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([current_user.id, new_email, action], salt='email')
            mail = Mail(app)
            msg = Message('Confirm new email address', sender='whatyouveread@gmail.com', recipients=[new_email])
            msg.body = 'You (or someone pretending to be you) has sent a request to associate this email address \
            with their What You\'ve Read account. Please follow this link to confirm this \
            was you: http://www.whatyouveread.com/confirm/{}'.format(email_hash)
            mail.send(msg)

            flash('Email address change almost complete: Please check your email and follow the link provided to confirm your new email address.')
            return redirect(url_for('settings'))
    else:
        return abort(405)

#confirm new or changed emailed address
@app.route('/confirm/<hash>')
def confirm(hash, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        decoded = serializer.loads(hash, salt='email', max_age=expiration)
    except:
        return "Error confirming your credentials." ### need to see what this returns and probably make more user friendly#############################################################################

    if decoded[2] == 'confirm':
        user = User.query.get(decoded[0])
        user.email = decoded[1]
        db.session.commit()
        flash('Thank you. Your email has been confirmed.')
        return redirect(url_for('settings'))

    if decoded[2] == 'change':
        return redirect(url_for('change_email', step=2, hash=hash))

@app.route('/u/<username>')
@login_required
def show_user_profile(username):
    # show the user profile for that user
    return 'Hello %s' % username

@app.route('/tag/<tag>/')
@login_required
def docs_by_tag(tag):
    docs = Documents.query.join(Tags).filter(Documents.user_id==current_user.id, Tags.name==tag).order_by(desc(Documents.created)).all()

    subheader = "tagged " + tag

    return render_template('read.html', docs=docs, subheader=subheader)

@app.route('/authors/<first_name> <last_name>')
@login_required
def docs_by_author(first_name, last_name):
    docs = Documents.query.join(Authors).filter(Documents.user_id==current_user.id). \
           filter(Authors.last_name==last_name).filter(Authors.first_name==first_name).order_by(desc(Documents.created)).all()

    subheader = "by " + first_name + " " + last_name

    return render_template('read.html', docs=docs, subheader=subheader)

#page of all tags
@app.route('/tags')
@login_required
def tags():
    #tags = Tags.query.filter_by(user_id=current_user.id).order_by(Tags.name).distinct()
    tags = db.session.query(Tags.name).filter_by(user_id=current_user.id).order_by(Tags.name).distinct()

    #to resize
    #first, need count of each
    #for tag in tags:
    #    tag.number = Tags.query.filter_by(name=tag.name).count()

    return render_template('tags.html', tags=tags)

#page of all authors
@app.route('/authors')
@login_required
def authors():
    authors = db.session.query(Authors.first_name, Authors.last_name).filter_by(user_id=current_user.id).order_by(Authors.last_name).distinct()

    return render_template('authors.html', authors=authors)

#deauthorize a service
@app.route('/deauthorize', methods=['GET', 'POST'])
@login_required
def deauthorize():
    if request.method == 'GET':
        return render_template('deauthorize.html', name=request.args.get('name'))
    elif request.method == 'POST':
        #what are they trying to deauthorize?
        service = request.form['name']
        confirm = request.form['deauthorize']
        if confirm == 'Yes':
            if service == 'Mendeley':
                #delete documents
                Documents.query.filter_by(user_id=current_user.id, service_id=1).delete()
                #delete tokens
                Tokens.query.filter_by(user_id=current_user.id, service_id=1).delete()
                #unset my flags for this
                current_user.mendeley = 0
                current_user.mendeley_update = 'NULL'
            if service == 'Goodreads':
                #delete documents
                Documents.query.filter_by(user_id=current_user.id, service_id=2).delete()
                #delete tokens
                Tokens.query.filter_by(user_id=current_user.id, service_id=2).delete()
                #unset my flags for this
                current_user.goodreads = 0
                current_user.goodreads_update = 'NULL'
            message = '{} has been deauthorized.'.format(service)
            db.session.commit()
        else:
            message = 'Deauthorization cancelled.'

        flash(message)
        return redirect(url_for('settings'))
    else:
        return redirect(url_for('index'))

#delete account
@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'GET':
        return render_template('delete_account.html')
    elif request.method == 'POST':
        confirm = request.form['delete_account']
        if confirm == 'Yes':
            current_password = request.form['wyr_current_password']
            #verify current password
            myctx = CryptContext(schemes=['pbkdf2_sha256'])
            if myctx.verify(current_password, current_user.password) == True:
                User.query.filter_by(id=current_user.id).delete()
                db.session.commit()
                flash('Account deleted. Sorry to see you go!')
                return redirect(url_for('index'))
            else:
                flash('Password incorrect.')
                return redirect(url_for('settings'))
        else:
            flash('Account deletion cancelled.')
            return redirect(url_for('settings'))
    else:
        return redirect(url_for('index'))

################################################################################
################################################################################
### MENDELEY ###################################################################
# uses Oauth 2, returns json
# service_id = 1

@app.route('/mendeley')
@login_required
def mendeley_login():

    mendeley = OAuth2Session(client_id=m['client_id'], redirect_uri=m['redirect_uri'], scope=m['scope'])
    authorization_url, state = mendeley.authorization_url(m['authorize_url'])

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/mendeley/authorization')
@login_required
def mendeley_authorize():
    # get vars from redirect
    code = request.args.get('code')
    state = request.args.get('state')

    # check against CSRF attacks
    if state != session['oauth_state']:
        return "Sorry, there has been an error."
    else:
        mendeley = OAuth2Session(m['client_id'], state=session['oauth_state'], redirect_uri=m['redirect_uri'])
        token = mendeley.fetch_token(m['token_url'], code=code, username=m['client_id'], password=m['client_secret'])

        #first get db object
        user = User.query.get(current_user.id)

        #update User db record - flag them as Mendeley user
        user.mendeley = 1
        #save token in Tokens table
        tokens = Tokens(user_id=user.id, service_id=1, access_token=token['access_token'], refresh_token=token['refresh_token'])
        db.session.add(tokens)
        db.session.commit()

        store_mendeley()

        return redirect(url_for('index'))

#gets doc info from mendeley and stores in database (only once, after initial authorization of service)
def store_mendeley():

    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, service_id=1).first()

    #for whatever reason, 0Auth2Session requires that its token parameter is in a dict
    token = {'access_token':tokens.access_token,
             'refresh_token':tokens.refresh_token}

    token['expires_in'] = time() - 10

    extra = {'client_id': m['client_id'],
             'client_secret': m['client_secret'],
             'refresh_token': tokens.refresh_token}

    #these next 15 lines are not what requests_oauthlib suggested, but they work

    #get 0auth object
    mendeley = OAuth2Session(m['client_id'], token=token)

    #get new access token (and possibly refresh token)
    new_token = mendeley.refresh_token(m['refresh_url'], **extra)

    #resave
    tokens.access_token = new_token['access_token']
    tokens.refresh_token = new_token['refresh_token']
    db.session.commit()

    #get new 0auth object with new token
    mendeley = OAuth2Session(m['client_id'], token=new_token)

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
        #skip items not read
        if doc['read'] == 0:
            continue

        new_doc = Documents(current_user.id, 1, doc['title'])
        new_doc.created=doc['created']
        new_doc.read=doc['read'] #stores as boolean
        new_doc.starred=doc['starred'] #stores as boolean
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

        if 'tags' in doc:
            for tag in doc['tags']:
                new_tag = Tags(current_user.id, new_doc.id, tag)
                db.session.add(new_tag)

        if 'authors' in doc:
            for author in doc['authors']:
                try:
                    new_author = Authors(current_user.id, new_doc.id, author['first_name'], author['last_name'], 0)
                except KeyError:
                    try:
                        new_author = Authors(current_user.id, new_doc.id, '', author['last_name'], 0)
                    except KeyError:
                        new_author = Authors(current_user.id, new_doc.id, author['first_name'], '', 0)
                db.session.add(new_author)

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


        #get file id to link to
        file_params = {'document_id':doc['id']}
        files = mendeley.get('https://api.mendeley.com/files', params=file_params).json()

        if files:
            for file in files:
                new_filelink = FileLinks(new_doc.id, file['id'])
                new_filelink.mime_type = file['mime_type']
                db.session.add(new_filelink)

        db.session.commit()

    current_user.mendeley_update = datetime.now()
    db.session.commit()

    return

#update doc info from Mendeley
def update_mendeley():

    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, service_id=1).first()

    #for whatever reason, 0Auth2Session requires that its token parameter is in a dict
    token = {'access_token':tokens.access_token,
             'refresh_token':tokens.refresh_token}

    token['expires_in'] = time() - 10

    extra = {'client_id': m['client_id'],
             'client_secret': m['client_secret'],
             'refresh_token': tokens.refresh_token}

    #these next 15 lines are not what requests_oauthlib suggested, but they work

    #get 0auth object
    mendeley = OAuth2Session(m['client_id'], token=token)

    #get new access token (and possibly refresh token)
    new_token = mendeley.refresh_token(m['refresh_url'], **extra)

    #resave
    tokens.access_token = new_token['access_token']
    tokens.refresh_token = new_token['refresh_token']
    db.session.commit()

    #get new 0auth object with new token
    mendeley = OAuth2Session(m['client_id'], token=new_token)

    #update since greater of: 1 day ago or last update
    one_day_ago = datetime.now() - timedelta(hours=24)
    since = current_user.mendeley_update if current_user.mendeley_update > one_day_ago else one_day_ago

    #parameters
    payload = {'limit':'500', 'modified_since':since.isoformat(), 'view':'all'}

    r = mendeley.get('https://api.mendeley.com/documents', params=payload)
    m_docs = r.json()

    #if no docs found, return
    if r.status_code != 200:
        return

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
        #skip items not read
        if doc['read'] == 0:
            continue

        #see if it already exists, delete if so and re-insert
        Documents.query.filter_by(user_id=current_user.id, service_id=1, native_doc_id=doc['id']).delete()
        db.session.commit()

        new_doc = Documents(current_user.id, 1, doc['title'])
        new_doc.created=doc['created']
        new_doc.read=doc['read'] #stores as boolean
        new_doc.starred=doc['starred'] #stores as boolean
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

        if 'tags' in doc:
            for tag in doc['tags']:
                new_tag = Tags(current_user.id, new_doc.id, tag)
                db.session.add(new_tag)

        if 'authors' in doc:
            for author in doc['authors']:
                try:
                    new_author = Authors(current_user.id, new_doc.id, author['first_name'], author['last_name'], 0)
                except KeyError:
                    try:
                        new_author = Authors(current_user.id, new_doc.id, '', author['last_name'], 0)
                    except KeyError:
                        new_author = Authors(current_user.id, new_doc.id, author['first_name'], '', 0)
                db.session.add(new_author)

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

        #get file id to link to
        file_params = {'document_id':doc['id']}
        files = mendeley.get('https://api.mendeley.com/files', params=file_params).json()

        if files:
            for file in files:
                new_filelink = FileLinks(new_doc.id, file['id'])
                new_filelink.mime_type = file['mime_type']
                db.session.add(new_filelink)
            db.session.commit()

    current_user.mendeley_update = datetime.now()
    db.session.commit()

    return

################################################################################
################################################################################
## WYR NATIVE   ################################################################
#service_id = 3


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'GET':
        #if this is from bookmarklet, pass along variables
        title = request.args.get('title')
        link = request.args.get('link')

        #also pass along tags for autocomplete
        new_tags = list()
        tags = list(db.session.query(Tags.name).filter_by(user_id=current_user.id).order_by(Tags.name).distinct().all())
        for tag in tags:
            new_tags.append(tag.name)

        return render_template('add.html', title=title, link=link, tags=new_tags)
    elif request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        year = request.form['year']
        tags = request.form['tags']
        authors = request.form['authors']
        editors = request.form['editors']
        notes = request.form['notes'].replace('\n', '<br>')
        submit = request.form['submit']

        #validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return(redirect(url_for('add')))

        #insert
        new_doc = Documents(current_user.id, 3, title)

        #add "http://" if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        new_doc.link = link
        new_doc.year = year
        new_doc.note = notes
        new_doc.read = 1
        new_doc.created = datetime.now()
        db.session.add(new_doc)
        db.session.commit()

        if tags:
            tags = tags.split(',')
            for tag in tags:
                if tag != ' ': #if user or autcomplately puts a space and comma at end, don't add empty tag
                    new_tag = Tags(current_user.id, new_doc.id, tag.strip())
                    db.session.add(new_tag)

        if authors:
            #get rid of a trailing ; so it doesn't make extra split with empty value in list
            if authors[-1] == ';':
                authors = authors[:-1]
            authors = authors.split(';')
            for author in authors:
                try:
                    author = author.split(',')
                    new_author = Authors(current_user.id, new_doc.id, author[1].strip(), author[0].strip(), 0)
                except IndexError:
                    new_author = Authors(current_user.id, new_doc.id, '', author[0].strip(), 0)
                db.session.add(new_author)
                db.session.commit()

        if editors:
            #get rid of a trailing ; so it doesn't make extra split with empty value in list
            if editors[-1] == ';':
                editors = editors[:-1]
            editors = editors.split(';')
            for editor in editors:
                try:
                    editor = editor.split(',')
                    new_editor = Authors(current_user.id, new_doc.id, editor[1].strip(), editor[0].strip(), 1)
                except IndexError:
                    new_editor = Authors(current_user.id, new_doc.id, '', editor[0].strip(), 1)

                db.session.add(new_editor)
                db.session.commit()

        db.session.commit()
        flash('Item added.')
        if submit == "Submit and Return Home":
            return redirect(url_for('index'))
        if submit == "Submit and Add Another":
            return redirect(url_for('add'))
        #if submitted from bookmarklet, just send to confirmation page, don't reload site (to mark it quicker)
        if submit == "Submit":
            return render_template('add.html', bookmarklet=1)
    else:
        return redirect(url_for('index'))

@app.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    if request.method == 'GET':
        #check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = Documents.query.filter_by(user_id=current_user.id, service_id=3, id=id).first()

        if doc:
            new_tags = ''
            new_authors_list = []
            new_editors_list = []
            new_authors = ''
            new_editors = ''

            new_editors_list = []

            #have to format tags, authors, and editors for form
            if doc.tags:
                for tag in doc.tags:
                    if tag != doc.tags[-1]:
                        new_tags += tag.name + ', '
                    else:
                        new_tags += tag.name

            if doc.authors: # need to add if/else for no first name?
                for author in doc.authors:
                    if author.role == 0:
                        new_authors_list.append(author)
                    else:
                        new_editors_list.append(author)

            for author in new_authors_list:
                if author != new_authors_list[-1]:
                    new_authors += author.last_name + ', ' + author.first_name + '; '
                else:
                    new_authors += author.last_name + ', ' + author.first_name

            for editor in new_editors_list:
                if editor != new_editors_list[-1]:
                    new_editors += editor.last_name + ', ' + editor.first_name + '; '
                else:
                    new_editors += editor.last_name + ', ' + editor.first_name

            #also pass along all tags for autocomplete
            all_tags = list()
            tags = list(db.session.query(Tags.name).filter_by(user_id=current_user.id).order_by(Tags.name).distinct().all())
            for tag in tags:
                all_tags.append(tag.name)

            return render_template('edit.html', doc=doc, tags=new_tags, all_tags=all_tags, authors=new_authors, editors=new_editors)
        else:
            return redirect(url_for('index'))

    elif request.method == 'POST':
        id = request.form['id']
        title = request.form['title']
        link = request.form['link']
        year = request.form['year']
        tags = request.form['tags']
        authors = request.form['authors']
        editors = request.form['editors']
        notes = request.form['notes'].replace('\n', '<br>')
        submit = request.form['submit']

        if submit == "Cancel":
            flash("Edit canceled.")
            return redirect(url_for('index'))

        #validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return(redirect(url_for('edit')))

        #update
        update_doc = Documents.query.filter_by(user_id=current_user.id, service_id=3, id=id).first()

        update_doc.title = title

        #add http:// if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        update_doc.link = link
        update_doc.year = year
        update_doc.note = notes
        update_doc.last_modified = datetime.now()
        db.session.commit()

        #delete tags and authors and reinsert

        Tags.query.filter_by(document_id=id).delete()
        Authors.query.filter_by(document_id=id).delete()

        if tags:
            tags = tags.split(',')
            for tag in tags:
                if tag != ' ': #if user or autcomplately puts a space and comma at end, don't add empty tag
                    update_tags = Tags(current_user.id, update_doc.id, tag.strip())
                    db.session.add(update_tags)

        if authors:
            #get rid of a trailing ; so it doesn't make extra split with empty value in list
            if authors[-1] == ';':
                authors = authors[:-1]
            authors = authors.split(';')
            for author in authors:
                try:
                    author = author.split(',')
                    update_authors = Authors(current_user.id, update_doc.id, author[1].strip(), author[0].strip(), 0)
                except IndexError:
                    update_authors = Authors(current_user.id, update_doc.id, '', author[0].strip(), 0)
                db.session.add(update_authors)

        if editors:
            #get rid of a trailing ; so it doesn't make extra split with empty value in list
            if editors[-1] == ';':
                editors = editors[:-1]
            editors = editors.split(';')
            for editor in editors:
                try:
                    editor = editor.split(',')
                    update_editors = Authors(current_user.id, update_doc.id, editor[1].strip(), editor[0].strip(), 1)
                except IndexError:
                    update_editors = Authors(current_user.id, update_doc.id, '', editor[0].strip(), 1)
                db.session.add(update_editors)

        db.session.commit()
        flash('Item edited.')
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        #check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = Documents.query.filter_by(user_id=current_user.id, service_id=3, id=id).first()
        if doc:
            return render_template('delete.html', doc=doc)
        else:
            return redirect(url_for('index'))
    elif request.method == 'POST':
        delete = request.form['delete']
        id = request.form['id']
        if delete == 'Delete':
            Documents.query.filter_by(user_id=current_user.id, service_id=3, id=id).delete()
            db.session.commit()
            flash("Item deleted.")
            return redirect(url_for('index'))
        if delete == 'Cancel':
            flash("Item not deleted.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

################################################################################
################################################################################
### Goodreads ##################################################################
#goodreads uses Oauth1, returns xml
#service_id 2

@app.route('/goodreads')
@login_required
def goodreads_login():
    goodreads = OAuth1Session(g['client_id'], client_secret=g['client_secret'])

    fetch_response = goodreads.fetch_request_token(g['request_token_url'])

    session['resource_owner_key'] = fetch_response.get('oauth_token')
    session['resource_owner_secret'] = fetch_response.get('oauth_token_secret')
    authorization_url = goodreads.authorization_url(g['authorize_url'])
    return redirect(authorization_url)

@app.route('/goodreads/authorization')
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

        #first get db object
        user = User.query.get(current_user.id)

        #update User db record - flag them as Goodreads user
        user.goodreads = 1
        #save token in Tokens table
        tokens = Tokens(user_id=user.id, service_id=2, access_token=access_token, access_token_secret=access_token_secret)
        db.session.add(tokens)
        db.session.commit()

        store_goodreads()

        return redirect(url_for('index'))
    else:
        flash('Authorization failed.')
        return redirect(url_for('settings'))

#gets books info from goodreads and stores in database (only once, after initial authorization of service)
def store_goodreads():

    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, service_id=2).first()

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
            new_doc = Documents(current_user.id, 2, doc.find('book/title').text)
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
                for shelf in doc.findall('shelves/shelf'):
                    #these are all in 'read' shelf, don't add that as a tag
                    if shelf.get('name') == 'read':
                        continue
                    new_tag = Tags(current_user.id, new_doc.id, shelf.get('name'))
                    db.session.add(new_tag)

            if doc.find('book/authors/author/name') is not None:
                for name in doc.findall('book/authors/author/name'):
                    #split one full name into first and last (jr's don't work right now #bug)
                    new_name = name.text.rsplit(' ', 1)
                    new_author = Authors(current_user.id, new_doc.id, new_name[0], new_name[1], 0)
                    db.session.add(new_author)

        i += 1

        db.session.commit()

    current_user.goodreads_update = datetime.now()
    db.session.commit()
    return

#update doc info from Goodreads
def update_goodreads():
    #unlike Mendeley, there doesn't appear to be a way to get books updated since X in goodreads,
    #so just have to delete and re-store all

    #delete
    Documents.query.filter_by(user_id=current_user.id, service_id=2).delete()

    #store
    store_goodreads()

    return

################################################################################
################################################################################
## IMPORT BOOKMARKS FROM HTML FILE #############################################
# service_id = 4 (this will allow me to delete all imported bookmarks if something goes wrong

from bs4 import BeautifulSoup

@app.route('/import', methods=['GET', 'POST'])
def import_bookmarks():
    if request.method == 'GET':
        return render_template('import.html')
    elif request.method == 'POST':
        file = request.files['bookmarks']
        file_extension = file.filename.rsplit('.', 1)[1]
        if file_extension != 'html':
            flash("Sorry, that doesn't look like a .html file.")
            return render_template('import.html')
        else:
            #better than first attempt (below), but only grabs most immediate folder (I think the way I want it)
            #but first need to display all folders to user, and let them choose which ones to import
            soup = BeautifulSoup(file, 'html.parser')
            bookmarks = []
            for each in soup.find_all('a'):
                if each.string != None:
                    parent_dt = each.find_parent('dl')
                    grandparent_dt = parent_dt.find_parent('dt')
                    if grandparent_dt != None:
                        previous_h3 = grandparent_dt.find_next('h3')
                    if previous_h3 != None:
                        #need to strip commas from any folders first
                        bookmarks.append({'folder':previous_h3.string, 'title':each.string, 'link':each.href})
            return render_template('import.html', var=bookmarks)


            """ this is the old code that imported all links (though erred on occassion when there was a nested folder above a link)
            for each in soup.find_all('a'):
                if each.string != None:
                    new_doc = Documents(current_user.id, 4, each.string) #will this (4 instead of 3) interfer with anything else?
                    new_doc.link = each['href']
                    new_doc.read = 1
                    #convert add_date (seconds from epoch format) to datetime
                    new_doc.created = datetime.fromtimestamp(int(each['add_date']))
                    db.session.add(new_doc)
                    db.session.commit()

                    if each.find_previous('h3'):
                        new_tag = Tags(current_user.id, new_doc.id, each.find_previous('h3').string)
                        db.session.add(new_tag)
                        db.session.commit()
            flash('Bookmarks successfully imported.')
            return redirect(url_for('index'))
            """

    else:
        abort(405)




