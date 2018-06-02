###############
### IMPORTS ###
###############

import re
import string
from datetime import datetime, timedelta
from collections import OrderedDict
from random import random
from passlib.context import CryptContext

from flask import Flask, render_template, request, session, redirect, url_for, \
    abort, flash
from flask_login import LoginManager, login_user, logout_user, \
    login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_misaka import Misaka
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, URLSafeSerializer
from jinja2 import evalcontextfilter, Markup, escape

from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

import stripe

from helpers import send_simple_message, get_stripe_info
from config import stripe_keys

###############
### CONFIG ####
###############

stripe.api_key = stripe_keys['secret_key']
md = Misaka(autolink='true', underline='true', strikethrough='true', html='false',
            no_html='true', highlight='true', hardwrap='true', wrap='true',
            fenced_code='true')
app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
md.init_app(app)

# import things that depend upon db
from db_functions import get_user_tags, get_user_authors, remove_to_read
from models import User, Documents, Tags, Bunches, Authors
from sources.native import native_blueprint
from sources.mendeley import mendeley_blueprint, import_mendeley
from sources.goodreads import goodreads_blueprint, import_goodreads
from sources.common import common_blueprint

#register blueprints
app.register_blueprint(native_blueprint)
app.register_blueprint(mendeley_blueprint)
app.register_blueprint(goodreads_blueprint)
app.register_blueprint(common_blueprint)


USE_SESSION_FOR_NEXT = True
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#######################
### CSRF PROTECTION ###
#######################

#from http://flask.pocoo.org/snippets/3/
#must use  <input name="_csrf_token" type="hidden" value="{{ csrf_token() }}"> in template forms
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


########################
### HELPER FUNCTIONS ###
########################

# redirect http to https
@app.before_request
def before_request():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)

#function for displaying datetime in jinja, defaulting to date like May 1, 1886
def datetimeformat(value, format='%B %d, %Y'):
    value = datetime.fromtimestamp(value)
    return value.strftime(format)
#now make it a filter
app.jinja_env.filters['datetime'] = datetimeformat

# new lines to breaks
# http://jinja.pocoo.org/docs/2.9/api/#custom-filters
_paragraph_re = re.compile(r'(?:\r\n|\r|\n){2,}')

@evalcontextfilter
def nl2br(eval_ctx, value):
    result = u'\n\n'.join(u'<p>%s</p>' % p.replace('\n', Markup('<br>\n'))
                          for p in _paragraph_re.split(escape(value)))
    if eval_ctx.autoescape:
        result = Markup(result)
    return result
#now make it a filter
app.jinja_env.filters['nl2br'] = nl2br

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id)
    if user.count() == 1:
        return user.one()
    return None


##############
### ROUTES ###
##############

'''
# testing
@app.route('/testing')
def testing():

    return render_template('testing.html')
'''


###########################
### MAIN DISPLAY ROUTES ###
###########################

@app.route('/')
def index():
    ''' Return documents or settings page for authenticated page, else return
    main sign up/info page.

    This also is where the function to update non-native docs is called.
    '''

    if current_user.is_authenticated:
        # set var for returning to proper page after edit or delete native doc
        session['return_to'] = url_for('index')

        one_week_ago = datetime.now() - timedelta(days=7)

        # update items from any sources if last update was > one week ago.
        # it's possible the user didn't immediately import source items after
        # authorizing, check for that
        if current_user.mendeley == 1 and not current_user.mendeley_update:
            import_mendeley('initial')
        if current_user.mendeley == 1 and current_user.mendeley_update < one_week_ago:
            import_mendeley('normal')

        if current_user.goodreads == 1 and not current_user.goodreads_update:
            import_goodreads('initial')
        if current_user.goodreads == 1 and current_user.goodreads_update < one_week_ago:
            import_goodreads('normal')

        docs = current_user.documents.order_by(desc(Documents.created))

        if not docs:
            flash("""You don't appear to have any documents yet. See below
            to authorize sources or import bookmarks. You can also add items
            individually.""")
            return redirect(url_for('settings'))

        return render_template('read.html', docs=docs, read_status='all')

    return render_template('index.html')


@app.route('/read')
@login_required
def read():
    ''' Return all read items.'''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('read')

    docs = Documents.query.filter_by(user_id=current_user.id, read=1).order_by(desc(Documents.created)).all()

    return render_template('read.html', docs=docs, read_status='read')


@app.route('/to-read')
@login_required
def to_read():
    ''' Return all unread items.'''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('to_read')

    docs = Documents.query.filter_by(user_id=current_user.id, read=0).order_by(desc(Documents.created)).all()

    return render_template('read.html', docs=docs, read_status='to-read')


@app.route('/tags')
@login_required
def tags():
    ''' Return page of all tags, which user can select to display documents with that tag. '''
    tags = get_user_tags()

    # group tags by their first letter, to enable jumping down page
    grouped_tags = OrderedDict()

    for tag in tags:
        if tag['name'][0] not in string.ascii_letters:
            try:
                grouped_tags['#'].append(tag)
            except KeyError:
                grouped_tags['#'] = []
                grouped_tags['#'].append(tag)
        else:
            try:
                grouped_tags[tag['name'][0].upper()].append(tag)
            except KeyError:
                grouped_tags[tag['name'][0].upper()] = []
                grouped_tags[tag['name'][0].upper()].append(tag)

    return render_template('tags.html', grouped_tags=grouped_tags)


@app.route('/<read_status>/tag/<tag>/')
@login_required
def docs_by_tag(read_status, tag):
    ''' Return all user's documents tagged <tag>. '''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('docs_by_tag', tag=tag, read_status=read_status)

    if read_status == 'read' or read_status == 'to-read':
        if read_status == 'read':
            status = 1
        if read_status == 'to-read':
            status = 0

        #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
        docs = current_user.documents.filter_by(read=status).filter(Documents.tags.any(name=tag)).order_by(desc(Documents.created)).all()

    else:
        #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
        docs = current_user.documents.filter(Documents.tags.any(name=tag)).order_by(desc(Documents.created)).all()

    return render_template('read.html', docs=docs, tagpage=tag, read_status=read_status) #tagpage is used for header


@app.route('/<read_status>/bunch/<name>') #, defaults={'read_status':'all'})
@login_required
def bunch(read_status, name):
    ''' Display docs from saved bunch '''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('bunch', read_status=read_status, name=name)

    # get the name, tags, read_stuats, and selector for this bunch
    bunch = Bunches.query.filter(Bunches.user_id==current_user.id, Bunches.name==name).one()

    if read_status == 'all':
        docs = current_user.documents.filter(Documents.tags.any(Tags.id.in_([t.id for t in bunch.tags]))).order_by(desc(Documents.created)).all()

    if read_status == 'read':
        docs = current_user.documents.filter(Documents.read==1, Documents.tags.any(Tags.id.in_([t.id for t in bunch.tags]))).order_by(desc(Documents.created)).all()


    if read_status == 'to-read':
        docs = current_user.documents.filter(Documents.read==0, Documents.tags.any(Tags.id.in_([t.id for t in bunch.tags]))).order_by(desc(Documents.created)).all()

    if bunch.selector == 'and':
        # couldn't figure out how to do this in one query, so this is probably inefficient, but...
        # take the query above (which get the "or" scenario), and
        # go through docs and eliminate them if they don't have every tag in tags
        for doc in docs[:]:
            for tag in bunch.tags:
                if tag.id not in [each.id for each in doc.tags]:
                    docs.remove(doc)
                    break

    #in this view, I could just return bunch=bunch, but bunches uses bunch_tag_names and selector
    return render_template('read.html', docs=docs,
                           bunch_tag_names=[tag.name for tag in bunch.tags],
                           bunch_name=name,
                           read_status=read_status,
                           selector=bunch.selector)


@app.route('/bunches', methods=['GET', 'POST'])
@login_required
def bunches():
    '''Let user select multiple tags and display the docs that fit the criteria.
    Include link to save the bunch, which takes place through bunch_save().'''
    if request.method == 'GET':
        tags = get_user_tags()
        bunches = Bunches.query.filter(Bunches.user_id==current_user.id).all()
        return render_template('bunches.html', tags=tags, bunches=bunches)

    # maybe turn this into a function? (most of it will be repeated for bunch()
    else:
        selector = request.form['selector'] # "and" or "or"
        bunch_tags = request.form.getlist('bunch_tags') # these are ids of chosen tags

        if not bunch_tags:
            flash("You didn't choose any tags.")
            return redirect(url_for('bunches'))

        if selector == 'or':
            docs = current_user.documents.filter(Documents.tags.any(Tags.id.in_([t for t in bunch_tags]))).order_by(desc(Documents.created)).all()

        #selector defaults to 'and'
        else:
            #couldn't figure out how to do this in one query, so this is probably inefficient, but...
            #first get the docs that have any of the tags chosen
            docs = current_user.documents.filter(Documents.tags.any(Tags.id.in_([t for t in bunch_tags]))).order_by(desc(Documents.created)).all()

            # now go through docs and eliminate them if they don't have every tag in tags
            for doc in docs[:]:
                for tag in bunch_tags:
                    if int(tag) not in [each.id for each in doc.tags]:
                        docs.remove(doc)
                        break

        #get tag names and put in list
        bunch_tag_names = []

        for tag in bunch_tags:
            tag = Tags.query.filter(Tags.id==tag).one()
            bunch_tag_names.append(tag.name)

        # store tag ids in session var to use in save_bunch (list var won't travel through form)
        session['bunch_tags'] = bunch_tags

        if not docs:
            flash("Sorry, no items matched your tag choices.")
            return redirect(url_for('bunches'))

        #return docs as well as list of tags and how they were chosen
        return render_template('read.html', docs=docs,
                                bunch_tag_names=bunch_tag_names,
                                selector=selector)


@app.route('/bunch/save', methods=['GET', 'POST'])
@login_required
def bunch_save():
    ''' Process a bunch save request from a user.'''

    selector = request.form['selector']
    bunch_name = request.form['bunch_name']

    new_bunch = Bunches(current_user.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    #get each tag object and append to new_bunch.tags
    for tag in session['bunch_tags']:
        existing_tag = Tags.query.filter(Tags.id==tag).one()
        new_bunch.tags.append(existing_tag)

    db.session.commit()

    flash("New bunch saved.")
    return redirect(url_for('bunches'))


@app.route('/bunch/edit', methods=['GET', 'POST'])
@login_required
def bunch_edit():
    ''' Let user add or remove tags from saved bunches.'''

    #show page to edit bunch name, selector, and tags
    if request.method == 'GET':
        bunch_name = request.args.get('name', '')
        bunch = Bunches.query.filter(Bunches.user_id==current_user.id, Bunches.name==bunch_name).one()
        tags = get_user_tags()
        return render_template('bunch_edit.html', bunch=bunch, tags=tags)

    #process
    else:
        if request.form['submit'] == 'cancel':
            flash('Edit canceled.')
            return redirect(url_for('bunches'))

        old_bunch_name = request.form['old_bunch_name']
        new_bunch_name = request.form['new_bunch_name']
        selector = request.form['selector']
        bunch_tags = request.form.getlist('bunch_tags') #ids

        if not bunch_tags:
            flash("You didn't choose any tags.")
            return redirect(url_for('bunches'))

        #try/except here
        try:
            bunch = Bunches.query.filter(Bunches.user_id==current_user.id,
                Bunches.name==old_bunch_name).one()
        except NoResultFound:
            flash('Sorry, there was an error fetching the bunch.')
            return redirect(url_for('bunches'))

        #check that name isn't duplicate
        if old_bunch_name != new_bunch_name:
            if Bunches.query.filter(Bunches.user_id==current_user.id, Bunches.name==new_bunch_name).first() != None:
                flash("You already have a bunch named " + new_bunch_name + ".")
                return redirect(url_for('bunch_edit', name=bunch.name))

        bunch.selector = selector
        bunch.name = new_bunch_name

        #get tag ids of tags currently in bunch
        old_bunch_tags = [tag.id for tag in bunch.tags]

        # add new tags
        for tag in bunch_tags[:]:
            if tag not in old_bunch_tags:
                tag = Tags.query.filter(Tags.id==tag).one()
                bunch.tags.append(tag)

        # remove old tags
        for old_tag in old_bunch_tags[:]:
            if old_tag not in bunch_tags:
                old_tag = Tags.query.filter(Tags.id==old_tag).one()
                bunch.tags.remove(old_tag)

        db.session.commit()

        flash('Bunch edited.')
        return redirect(url_for('bunches')) # or maybe this should go to bunch/<name>?


@app.route('/bunch/delete', methods=['GET', 'POST'])
@login_required
def bunch_delete():
    ''' Let user add or remove tags from saved bunches.'''

    if request.method == 'GET':
        name = request.args.get('name', '')
        bunch_name = request.args.get('bunch_name')
        return render_template('bunch_delete.html', bunch_name=name)

    # maybe turn this into a function? (most of it will be repeated for bunch()
    else:
        if request.form['submit'] == 'cancel':
            flash('Deletion canceled.')
            return redirect(url_for('bunches'))

        bunch_name = request.form['bunch_name']

        #should do a try/except here
        bunch = Bunches.query.filter(Bunches.user_id==current_user.id,
            Bunches.name==bunch_name).one()

        db.session.delete(bunch)
        db.session.commit()

        flash('Bunch deleted.')
        return redirect(url_for('bunches'))


@app.route('/authors')
@login_required
def authors():
    ''' Display all authors for user's documents. '''
    authors = get_user_authors()

    # group authors by first letter of last name, to enable jumping down page
    grouped_authors = OrderedDict()

    for author in authors:
        if author['last_name'][0] not in string.ascii_letters:
            try:
                grouped_authors['#'].append(author)
            except KeyError:
                grouped_authors['#'] = []
                grouped_authors['#'].append(author)
        else:
            try:
                grouped_authors[author['last_name'][0].upper()].append(author)
            except KeyError:
                grouped_authors[author['last_name'][0].upper()] = []
                grouped_authors[author['last_name'][0].upper()].append(author)

    return render_template('authors.html', grouped_authors=grouped_authors)


@app.route('/<read_status>/author/<author_id>')
@login_required
def docs_by_author(read_status, author_id):
    ''' Return all documents by particular author. '''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('docs_by_author', author_id=author_id, read_status=read_status)

    #author = Authors.id=id.one()
    author = Authors.query.filter_by(id=author_id).one()

    if read_status == 'read' or read_status == 'to-read':
        if read_status == 'read':
            status = 1
        if read_status == 'to-read':
            status = 0

        #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
        docs = current_user.documents.filter_by(read=status).filter(Documents.authors.any(id=author_id)).\
            order_by(desc(Documents.created)).all()

    else:
        #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
        docs = current_user.documents.filter(Documents.authors.any(id=author_id)).\
            order_by(desc(Documents.created)).all()

    # only return docs author info if user has docs by that author
    # this ensures one user can't type in an id and see an author another user has
    if not docs:
        if read_status == 'read':
            flash("Sorry, you have no read documents by that author.")
        elif read_status == 'to-read':
            flash("Sorry, you have no to-read documents by that author.")
        else:
            flash("Sorry, you have no documents by that author.")
        return redirect(url_for('authors'))

    else:
        #authorpage, first_name, last_name used for header
        return render_template('read.html', docs=docs, authorpage=1, \
            author=author, first_name=author.first_name, last_name=author.last_name, read_status=read_status)


@app.route('/lastmonth')
@login_required
def last_month():
    ''' Return all read items from last month, in chronological order'''

    # set var for returning to proper page after edit or delete native doc
    session['return_to'] = url_for('last_month')

    one_month_ago = datetime.today() - timedelta(days=31)

    docs = Documents.query.filter(Documents.user_id==current_user.id, Documents.read==1,
                                  Documents.created >= one_month_ago).order_by(Documents.created).all()

    return render_template('read.html', docs=docs, read_status='read', last_month=1)



#############################
### ADMIN/SETTINGS ROUTES ###
#############################

@app.route('/u/<username>')
@login_required
def show_user_profile(username):
    ''' show the user profile for that user '''
    return 'Hello {}'.format(username)


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    ''' Sign up page.
    Display form for new user to fill out, validate it, and create new user account.
    '''

    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        # do checks, send email to user to complete sign up

        username = request.form['wyr_username']
        email = request.form['email']

        #checks
        error = 0
        if User.query.filter_by(username=username).count() > 0:
            error = 1
            flash('Sorry, username {} is already taken.'.format(username))
        if User.query.filter_by(email=email).count() > 0:
            error = 1
            flash('Sorry, the email address {} is already in use.'.format(email))
        if '@' not in email:
            error = 1
            flash('The email you entered does not appear to be valid.')
        if error == 1:
            return redirect(url_for('sign_up'))

        #generate the token, send the email, then return user to index
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email_hash = serializer.dumps([username, email], salt='sign_up')

        subject = 'Activate your account'
        text = """Please activate your account by following
        <a href="http://www.whatyouveread.com/activate?code={}">this link</a>.<br>
        <br>
        -Kris @ What You've Read""".format(email_hash)

        send_simple_message(email, subject, text)

        #redirect them back to home page
        flash('Please check your email to activate your account.')
        return redirect(url_for('index'))
    else:
        abort(405)


@app.route('/activate', methods=['GET', 'POST'])
def activate():
    ''' Activate user account - finish the sign up process now that the email
    is verified - get user's password, do checks on it, and insert user into database
    '''

    #send user to form to set password if hash is good
    if request.method == 'GET':

        #first, pull user's email and username out of hash
        hash = request.args.get('code')
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            decoded = serializer.loads(hash, salt='sign_up', max_age=3600)
        except SignatureExpired:
            flash('Activation period expired. Please sign up again.')
            return redirect(url_for('index'))
        except:
            flash("Error activating your account. Please sign up again below.")
            return redirect(url_for('index'))

        return render_template('activate.html', username=decoded[0], email=decoded[1])

    # get user's desired password, check, add account
    if request.method == 'POST':

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        #checks - password
        if password != confirm_password:
            flash("Your passwords did not match. Please try again.")
            return render_template('activate.html', username=username, email=email)
        if len(password) < 5:
            flash("Your password is too short. Please try again.")
            return render_template('activate.html', username=username, email=email)
        #checks - if user already completed sign up, redirect
        if User.query.filter_by(username=username).count() > 0:
            flash("You've already activated your account.")
            return redirect(url_for('index'))

        #use passlib to encrypt password
        myctx = CryptContext(schemes=['pbkdf2_sha256'])
        hashed_password = myctx.encrypt(password)

        #add user
        user = User(username, hashed_password, email)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        flash('Thank you. Your account has been activated.')
        return redirect(url_for('settings'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    ''' Let users log in. '''
    if request.method == 'GET':
        return render_template('index.html', next=request.args.get('next'))
    else:
        username = request.form['wyr_username']
        password = request.form['wyr_password']
        remember = request.form.getlist('remember')

        # get/set value of 'next' if it exists, in order to redirect user back
        # to a page dec'd @login_required they may have tried to log in from
        next = 'index'
        if 'next' in session:
            next = session['next']

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

            else:
                flash('Sorry, the password is incorrect.')

        else:
            flash('Username does not exist.')

        return redirect(url_for(next))


@app.route('/logout')
def logout():
    ''' Log out users. '''
    logout_user()
    flash('You\'ve been logged out.')
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    ''' Settings page. '''
    if request.method == 'GET':
        return render_template('settings.html')
    elif request.method == 'POST':
        current_user.auto_close = request.form['auto_close']
        current_user.markdown = request.form['markdown']
        current_user.include_m_unread = request.form['include_m_unread']
        current_user.include_g_unread = request.form['include_g_unread']
        db.session.commit()

        # if user is changing pref to exclude to-read items in Mendely, delete any
        # existing Mendeley docs tagged as to-read
        if current_user.include_m_unread == 0 and request.form['old_include_m_unread'] == '1':
            remove_to_read(1)

        # if user is changing pref to exclude to-read items in Goodreads, delete any
        # existing Goodreads books tagged as to-read
        if current_user.include_g_unread == 0 and request.form['old_include_g_unread'] == '1':
            remove_to_read(2)

        # if user is change pref to include to-read items in Mendeley, set var
        # do a full update (not limit to recent items)
        if current_user.include_m_unread == 1 and request.form['old_include_m_unread'] == '0':
            import_mendeley('unread_update')

        # if user is change pref to include to-read items in Mendeley, set var
        # do a full update (not limit to recent items)
        if current_user.include_g_unread == 1 and request.form['old_include_g_unread'] == '0':
            import_goodreads('unread_update')

        flash("Your preferences have been updated.")
        return redirect(url_for('settings'))
    else:
        return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    ''' Let users change password '''

    if request.method == 'GET':
        return render_template('change_password.html')
    elif request.method == 'POST':
        if request.form['submit'] == 'Cancel':
            flash('Password change cancelled.')
            return redirect(url_for('settings'))

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

                # send user email to confirm, allow reset of password
                #hash for confirm change
                serializer = URLSafeSerializer(app.config['SECRET_KEY'])
                email_hash = serializer.dumps([current_user.email], salt='reset_password')

                to = current_user.email
                subject = 'Password Change'
                text = """The password for your What You've Read account has been
                changed. If this was not you, someone has access to your account. You should
                <a href="http://www.whatyouveread.com/reset_password?code={}">reset your
                password</a> immediately.<br>
                <br>
                -Kris @ What You've Read""".format(email_hash)

                send_simple_message(to, subject, text)

                flash('Your password has been updated.')
                return redirect(url_for('settings'))
        else:
            flash('Password is incorrect.')
            return redirect(url_for('change_password'))
    else:
        return abort(405)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    ''' Display form to send email link to reset password; display form to
    reset password if user clicked on confirmation link. '''
    if request.method == 'GET':

        # display form to enter email to initiate reset process
        if not request.args.get('reset'):
            return render_template('forgot_password.html')

        # otherwise, user has already clicked on confirmation link
        hash = request.args.get('reset')

        return render_template('reset_password.html', hash=hash)

    elif request.method == 'POST':
        if request.form['send_email'] == "Cancel":
            return redirect(url_for('index'))

        email = request.form['email']

        #check we have the email
        if User.query.filter_by(email=email).count() > 0:
            #generate the token, send the email, then return user to login
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([email], salt='forgot_password')

            subject = 'Reset Forgotten Password'
            text = """What You've Read has received a request to reset your
            forgotten password. Please follow
            <a href="http://www.whatyouveread.com/forgot_password?reset={}">this link</a>
            to reset it.""".format(email_hash)

            send_simple_message(email, subject, text)

            flash('An email has been sent to you. Please follow the link provided to reset your password.')
            return redirect(url_for('index'))

        else:
            flash('No account with that email exists.')
            return redirect(url_for('index'))
    else:
        return abort(405)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    ''' allow user to reset password
    hash: variable emailed in link to user to confirm resetting
    '''

    # user has clicked on reset password link in an email sent to them about
    # changing their email address
    if request.method == 'GET':
        if request.args.get('code'):
            return render_template('reset_password.html', hash=request.args.get('code'), untimed='true')
        return redirect(url_for('index'))

    # process the password reset request
    elif request.method == 'POST':
        if request.form['submit'] == 'cancel':
            flash("Password reset canceled.")
            return redirect(url_for('index'))

        hash = request.form['hash']
        untimed = ''

        # use untimed version of URL serializer - user has noticed attempt to change
        # their email and is resetting password
        if request.form['untimed'] == 'true':
            untimed = request.form['untimed']
            serializer = URLSafeSerializer(app.config['SECRET_KEY'])
            try:
                decoded = serializer.loads(hash, salt='reset_password')
            except:
                flash("Sorry, there was an error. Please try again.")
                return redirect(url_for('index'))

        #use timed version - user forgot password and was sent link to reset
        else:
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            try:
                decoded = serializer.loads(hash, salt='forgot_password', max_age=3600)
            except SignatureExpired:
                flash('The link has expired; password not reset.')
                return redirect(url_for('index'))
            except:
                flash("Sorry, there was an error. Please try again.")
                return redirect(url_for('index'))

        #try to update password
        try:
            user = User.query.filter_by(email=decoded[0]).one()
        except NoResultFound:
            flash('Could not find an account associated with that email address.')
            return redirect(url_for('index'))
        else:
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if len(password) < 5:
                flash('Password is too short. Please try again.')
                return render_template('reset_password.html', hash=hash, untimed=untimed)
            elif password != confirm_password:
                flash('The confirmation password did not match the new password you entered.')
                return render_template('reset_password.html', hash=hash, untimed=untimed)
            else:
                #use passlib to encrypt password and then update it
                myctx = CryptContext(schemes=['pbkdf2_sha256'])
                hashed_password = myctx.encrypt(password)
                user.password = hashed_password
                db.session.commit()

                flash('Your password has been updated. Please use it to login.')
                return redirect(url_for('login'))

    else:
        return abort(405)


@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    ''' Change user email '''
    # change email or display form to enter new email or send confirmation
    if request.method == 'GET':

        # if this is coming from link sent to current email address, send another
        # to new email address
        if request.args.get('code'):
            hash = request.args.get('code')
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            try:
                decoded = serializer.loads(hash, salt='change_email', max_age=3600)
            except:
                flash("""Error confirming your credentials. Please try again later or contact
                us if this problem continues to exist.""")
                return redirect(url_for('settings'))

            #if for some reason some other logged in user clicks the link
            if decoded[0] != current_user.username:
                flash("Username does not match. Email not changed.")
                redirect(url_for('index'))

            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([current_user.username, decoded[1]], salt='change_email')

            to = decoded[1]
            subject = 'Email address change'
            text = """What You've Read has received a request to change your email
            address to this one. If this was you, please follow
            <a href="http://www.whatyouveread.com/change_email?confirm={}">
            this link</a> to confirm.""".format(email_hash)

            send_simple_message(to, subject, text)

            flash("""Please check your email at your new email address and
            follow the link provided to confirm it.""")
            return redirect(url_for('settings'))

        #if this is coming from the link sent to confirm the change, change it
        if request.args.get('confirm'):
            hash = request.args.get('confirm')
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            try:
                decoded = serializer.loads(hash, salt='change_email', max_age=3600)
            except:
                flash("""Error confirming your credentials. Please try again later or contact
                us if this problem continues to exist.""")
                return redirect(url_for('settings'))

            #if for some reason some other logged in user clicks the link
            if decoded[0] != current_user.username:
                flash("Username does not match. Email not changed.")
                redirect(url_for('index'))

            current_user.email = decoded[1]
            db.session.commit()
            flash('Your email has been changed.')
            return redirect(url_for('settings'))

        #else, display the original form to request the email change
        return render_template('change_email.html')

    # send email to current email address to confirm the change
    elif request.method == 'POST':
        if request.form['submit'] == "Cancel":
            flash('Email change cancelled.')
            return redirect(url_for('settings'))

        new_email = request.form['new_email']
        password = request.form['password']

        #minimum check that it's an email:
        if '@' not in new_email:
            flash('That didn\'t look like an email address. Please try again.')
            return redirect(url_for('change_email'))

        #check if email already in use in another account
        if User.query.filter_by(email=new_email).count() > 0:
            flash('Sorry, that email address is already in use.')
            return redirect(url_for('change_email'))

        # verify password
        myctx = CryptContext(schemes=['pbkdf2_sha256'])
        if myctx.verify(password, current_user.password) == True:

            #hash for confirm change
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email_hash = serializer.dumps([current_user.username, new_email], salt='change_email')

            # hash for resetting password if user didn't initiate this (change salt
            # and use regular serializer, not timed one)
            serializer2 = URLSafeSerializer(app.config['SECRET_KEY'])
            email_hash2 = serializer2.dumps([current_user.email], salt='reset_password')

            to = current_user.email
            subject = 'Email address change'
            text = """What You've Read has received a request to change your email
            address to {}. If this was you, please follow
            <a href="http://www.whatyouveread.com/change_email?code={}">
            this link</a> to confirm.
            <br><br>
            If this was not you, someone has access to your account. You should
            <a href="http://www.whatyouveread.com/reset_password?code={}">reset your
            password</a> immediately.""".format(new_email, email_hash, email_hash2)

            send_simple_message(to, subject, text)

            flash("""Please check your email at your current email address
                and follow the link provided.""")
            return redirect(url_for('settings'))

        else:
            flash('Password is incorrect.')
            return redirect(url_for('change_email'))
    else:
        return abort(405)


@app.route('/screenshots')
def screenshots():
    ''' screenshots of WYR for new potential users '''
    return render_template('screenshots.html')


@app.route('/contact', methods = ['GET', 'POST'])
def contact():
    ''' contact me '''
    if request.method == 'GET':
        return render_template('contact.html')
    elif request.method == 'POST':

        #if user is logged in, we already have their info, else have to get it
        if current_user.is_authenticated:
            name = current_user.username
            email = current_user.email
        else:
            email = request.form['email']
            name = request.form['name']

        submit = request.form['submit']
        comments = request.form['comments']

        if submit == "Cancel":
            return redirect(url_for('index'))

        if comments == '':
            flash("You didn't add any comments.")
            return render_template('contact.html')

        to = 'whatyouveread@gmail.com'
        subject = 'Submitted comments on WYR'
        text = '{} ({}) submitted these comments:<br>{}'.format(name, email, comments)

        send_simple_message(to, subject, text)

        flash("Your comments have been sent. Thank you.")

    return redirect(url_for('index'))


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    ''' delete account, after password validation '''
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


@app.route('/donate')
@login_required
def donate():
    ''' get user stripe info and send to donate page'''
    donor, subscription = get_stripe_info()

    return render_template('donate.html', key=stripe_keys['publishable_key'], donor=donor, subscription=subscription)


@app.route('/cancel_donation', methods=['GET', 'POST'])
@login_required
def cancel_donation():
    ''' let user cancel a donation '''
    if request.method == 'GET':
        return render_template('cancel_donation.html')

    if request.method == 'POST':
        #get user stripe info
        donor, subscription = get_stripe_info()

        #otherwise process form
        if request.form['cancel_next_donation'] == 'Yes':
            #cancel it
            subscription = stripe.Subscription.retrieve(subscription.id)
            subscription.delete()

            flash('Your scheduled donation has been cancelled.')
        else:
            flash('Your scheduled donation has NOT been cancelled.')

        #get user stripe info
        donor, subscription = get_stripe_info()

        return render_template('donate.html', key=stripe_keys['publishable_key'], donor=donor, subscription=subscription)


@app.route('/charge', methods=['GET', 'POST'])
@login_required
def charge():
    ''' charge user's donation to their payment method '''
    if request.method == 'POST':

        # Get the credit card details submitted by the form
        token = request.form['stripeToken']
        plan = request.form['plan']
        sub_id = request.form['sub_id']
        customer_id = request.form['customer_id']

        # Create the charge on Stripe's servers - this will charge the user's card
        try:
            #if current subscription, update it, else create new customer (and subscription)
            if sub_id != '':
                customer = stripe.Customer.retrieve(customer_id)
                subscription = stripe.Subscription.retrieve(sub_id)
                if plan == '0': #################I'm fairly certain I can delete this if
                    #cancel it
                    subscription.delete()
                else:
                    #update it
                    subscription.plan = plan
                    subscription.save()
            else:
                customer = stripe.Customer.create(email=current_user.email, plan=plan, source=token)

        except stripe.error.CardError as e:
            flash('Sorry, your card has been declined. Please try again.')
            return redirect(url_for('donate'))
        except stripe.error.RateLimitError as e:
            # Too many requests made to the API too quickly
            flash('Sorry, the server has been overloaded. Please try again in a moment.')
            return redirect(url_for('donate'))

        except stripe.error.InvalidRequestError as e:
            # Invalid parameters were supplied to Stripe's API
            flash('Sorry, we have made an error(1). Please try again later.')
            return redirect(url_for('donate'))

        except stripe.error.AuthenticationError as e:
            # Authentication with Stripe's API failed
            # (maybe you changed API keys recently)
            flash('Sorry, we have made an error(2). Please try again later.')
            return redirect(url_for('donate'))

        except stripe.error.APIConnectionError as e:
            # Network communication with Stripe failed
            flash('Sorry, we have made an error(3). Please try again later.')
            return redirect(url_for('donate'))

        except stripe.error.StripeError as e:
            # Display a very generic error to the user, and maybe send yourself an email
            pass

        except Exception as e:
            # Something else happened, completely unrelated to Stripe
            flash('Sorry, we have made an error(4). Please try again later.')
            return redirect(url_for('donate'))

        #add the customer.id to user table, as stripe_id
        current_user.stripe_id = customer.id
        db.session.commit()

        flash("""Thanks for the donation. A receipt will be emailed to you.
            If you do not get it, contact me.""")

    donor, subscription = get_stripe_info()

    return render_template('donate.html', key=stripe_keys['publishable_key'], donor=donor, subscription=subscription)


@app.route('/donate_paypal')
def paypal():
    return render_template('donate_paypal.html')


#handle 404 - this was throwing errors where it shouldn't, so disabled
#@app.errorhandler(404)
#def page_not_found(e):
#    flash("Sorry, that page wasn't found.")
#    return redirect(url_for('index'))


@app.errorhandler(413)
def file_too_big(e):
    flash('Sorry, that file is too big.')
    return render_template('import.html')
