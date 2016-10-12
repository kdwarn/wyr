from flask import Flask, render_template, request, session, redirect, url_for, \
    abort, flash, jsonify
from flask.ext.login import LoginManager, login_user, logout_user, \
    login_required, current_user
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc, func, distinct, text
from requests_oauthlib import OAuth2Session, OAuth1Session
from oauthlib.oauth2 import InvalidGrantError
from xml.etree import ElementTree
from time import time
from config import m, g, stripe_keys, mailgun
from passlib.context import CryptContext
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from random import random
from math import ceil
import stripe
import requests

#from testing import test_doc, test_tag, test_author

stripe.api_key = stripe_keys['secret_key']

app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)

from models import User, Tokens, Documents, Tags, Authors, FileLinks
from wyr.sources.native import native

app.register_blueprint(native)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

#function for displaying datetime in jinja, defaulting to date like May 1, 1886
def datetimeformat(value, format='%B %d, %Y'):
    value = datetime.fromtimestamp(value)
    return value.strftime(format)
#now make it a filter
app.jinja_env.filters['datetime'] = datetimeformat


@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id)
    if user.count() == 1:
        return user.one()
    return None

def send_simple_message(to, subject, text):
    """ send email via mailgun """
    return requests.post(
        mailgun['messages_url'],
        auth=('api', mailgun['api_key']),
        data={'from': mailgun['from'],
              'h:Reply-To': mailgun['reply_to'],
              'to': to,
              'subject': subject,
              'html': text})

def get_stripe_info():
    """ get user's Stripe info """
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

"""
@app.route('/testing')
def testing():
    pass
"""

@app.route('/sandbox/ <two>', defaults={'one': None})
def sandbox(one, two):
    variable = [one, two]
    #if not one:
    #    variable = ['empty', two]
    return render_template('sandbox.html', variable=variable)


@app.route('/')
def index():
    ''' Return documents or settings page for autenticated page, else return
    main sign up/info page.

    This also is where the function to update non-native docs is called.
    '''
    if current_user.is_authenticated:
        # fetch and display read items from various services
        then = datetime.now() - timedelta(days=7)
        if current_user.mendeley == 1 and current_user.mendeley_update < then:
            update_mendeley()
        """ disabling for now
        if current_user.goodreads == 1 and current_user.goodreads_update < then:
            update_goodreads()
        """
        # put user's docs into variable to return
        docs = current_user.documents.order_by(desc(Documents.created))

        if not docs:
            flash("""You don't appear to have any read documents yet. See below
            to authorize services or import bookmarks. You can also add items
            individually.""")
            return redirect(url_for('settings'))

        return render_template('read.html', docs=docs)
    else:
        return render_template('index.html')

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

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    ''' Sign up page.

    Display form for new user to fill out, validate it, and create new user account.

    '''

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

        #use passlib to encrypt password
        myctx = CryptContext(schemes=['pbkdf2_sha256'])
        hash = myctx.encrypt(password)

        user = User(username=username, password=hash, email=email)
        db.session.add(user)
        db.session.commit()

        #do this after first login instead
        #generate the token, send the email, then return user to login
        action = 'confirm' #used to differentiate between confirming and changing email in confirm()
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email_hash = serializer.dumps([user.id, email, action], salt='email')

        subject = 'Confirm your email address'
        text = """Welcome to What You've Read. Please confirm your email by following
        this link:<br> http://www.whatyouveread.com/confirm/{}.""".format(email_hash)

        send_simple_message(email, subject, text)

        #log the user in
        login_user(user)

        #redirect them back to home page
        flash('Welcome to What You\'ve Read, {}!'.format(username))
        return redirect(url_for('index'))
    else:
        abort(405)

@app.route('/login', methods=['GET', 'POST'])
def login():
    ''' Let users log in. '''
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
    ''' Log out users. '''
    logout_user()
    flash('You\'ve been logged out.')
    return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    ''' Settings page. '''
    return render_template('settings.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    ''' Let users change password, set email to confirm. '''
    if request.method == 'GET':
        return render_template('change_password.html')
    elif request.method == 'POST':
        if request.form['submit'] == 'Cancel':
            flash('Password change cancelled.')
            return redirect(url_for('settings'))

        current_password = request.form['wyr_current_password']
        new_password = request.form['wyr_new_password']
        confirm_password = request.form['wyr_confirm_password']
        submit = request.form['submit']

        if submit == 'Cancel':
            return redirect(url_for('settings'))

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

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    ''' Display form to send email link to reset password. '''
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

            subject = 'Reset password'
            text = """To reset your password, please follow this link:<br>
                http://www.whatyouveread.com/reset_password/{}""".format(email_hash)

            send_simple_message(email, subject, text)

            flash('An email has been sent to you. Please follow the link provided to reset your password.')
            return redirect(url_for('index'))

        else:
            flash('No account with that email exists.')
            return redirect(url_for('index'))
    else:
        return abort(405)

@app.route('/reset_password/<hash>', methods=['GET', 'POST'])
def reset_password(hash, expiration=3600):
    '''
    GET: form to change password, from link emailed to user
    POST: change the password
    '''
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

@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    '''
    Change user email, in conjuction with confirm()
    '''
    if request.method == 'GET':
        return render_template('change_email.html')
    elif request.method == 'POST':
        if request.form['submit'] == "Cancel":
            flash('Email change cancelled.')
            return redirect(url_for('settings'))

        new_email = request.form['new_email']
        confirm_email = request.form['confirm_email']

        #minimum check that it's an email:
        if '@' not in new_email:
            flash('That didn\'t look like an email address. Please try again.')
            return redirect(url_for('change_email'))

        #check if email already in use in another account
        if User.query.filter_by(email=new_email).count() > 0:
            flash('Sorry, that email address is already in use.')
            return redirect(url_for('change_email'))

        #check that they match
        if new_email != confirm_email:
            flash("""The emails you entered did not match. Please try again. (This
                is a safety feature to make sure you are entering the correct email.)""")
            return redirect(url_for('change_email'))

        action = 'change' #used to differentiate between confirming and changing email in confirm()
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email_hash = serializer.dumps([current_user.id, current_user.email, action, new_email], salt='email')

        to = current_user.email
        subject = 'Email address change'
        text = """What You've Read has received a request to change your email
            address. If this was you, please follow this link to confirm:<br><br>
            http://www.whatyouveread.com/confirm/{}<br><br>
            If this was not you, someone has access to your account. You should
            <a href="http://www.whatyouveread.com/forgot_password">reset your
            password</a> immediately.""".format(email_hash)

        send_simple_message(to, subject, text)

        flash("""Please check your email and follow the link provided to confirm
            your new email address.""")
        return redirect(url_for('settings'))

    else:
        return abort(405)


@app.route('/confirm/<hash>')
def confirm(hash, expiration=3600):
    '''
    confirm new or changed emailed address
    '''
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
        user = User.query.get(decoded[0])
        user.email = decoded[3]
        db.session.commit()
        flash('Your new email address has been saved.')
        return redirect(url_for('settings'))

@app.route('/u/<username>')
@login_required
def show_user_profile(username):
    # show the user profile for that user
    return 'Hello {}'.format(username)

#items by tag
@app.route('/tag/<tag>/')
@login_required
def docs_by_tag(tag):
    ''' Return all user's documents tagged <tag>. '''

    #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
    docs = current_user.documents.filter(Documents.tags.any(name=tag)).order_by(desc(Documents.created)).all()

    #tagpage is used for both header and to return user to list of docs by tag if user editing or deleting from there
    return render_template('read.html', docs=docs, tagpage=tag)


@app.route('/authors/<first_name> <last_name>')
@login_required
def docs_by_author(first_name, last_name):
    ''' Return all documents by particular author. '''

    #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
    docs = current_user.documents.filter(Documents.authors.any(first_name=first_name)).\
        filter(Documents.authors.any(last_name=last_name)).order_by(desc(Documents.created)).all()

    #authorpage, first_name, last_name used for header
    return render_template('read.html', docs=docs, authorpage=1, first_name=first_name, last_name=last_name)


@app.route('/authors/ <last_name>')
@login_required
def docs_by_author_last(last_name):
    ''' Same as above, but in the special case where there is only a last name (institional name) '''

    #http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#building-a-many-to-many-relationship
    docs = current_user.documents.filter(Documents.authors.any(last_name=last_name)).order_by(desc(Documents.created)).all()

    #authorpage, first_name, last_name used for header
    return render_template('read.html', docs=docs, authorpage=1, last_name=last_name)


@app.route('/tags')
@login_required
def tags():
    ''' Return page of all tags, which user can select to display documents with that tag. '''
    tags = get_user_tags()
    return render_template('tags.html', tags=tags)

@app.route('/bunches', methods=['GET', 'POST'])
@login_required
def bunches():
    '''
    Let user select multip tags and display the docs that fit the criteria.

    Include link to save the bunch, which takes place through save_bunch().

    '''
    if request.method == 'GET':
        tags = db.session.query(Tags.name).filter_by(user_id=current_user.id).order_by(Tags.name).distinct()
        return render_template('bunches.html', tags=tags)
    else:
        selector = request.form['selector'] # "and" or "or"
        tags = request.form.getlist('tags')

        if not tags:
            flash("You didn't choose any tags.")
            return redirect(url_for('bunches'))

        if selector == 'or':
            #select docs that have any of the tags selected
            docs = Documents.query.join(Tags).filter(Documents.user_id==current_user.id, Tags.name.in_(tags)).order_by(desc(Documents.created)).all()

        #defaults to 'and'
        else:
            #first need to readjust tags, documents, document_tags tables
            #this is not quite right - I need to utilize a JOIN here but I don't understand them well enough
            #after much struggling, slightly adapted this:
            #http://stackoverflow.com/questions/13349832/sqlalchemy-filter-to-match-all-instead-of-any-values-in-list
            docs = db.session.query(Documents).order_by(desc(Documents.created))
            for tag in tags:
                docs = docs.filter(Documents.tags.any(Tags.name==tag))


        if not docs:
            flash("Sorry, no items matched your tag choices.")
            return redirect(url_for('bunches'))

        #send back docs as well as list of tags and how they were chosen
        return render_template('read.html', docs=docs, tags=tags, selector=selector)

@app.route('/save_bunch', methods=['POST'])
@login_required
def save_bunch():
    ''' Process a bunch save request from a user.'''

    #user wants to save, send them to form to provide name
    if request.form['save'] == '1':
        tags = request.form.getlist('tags')
        render_template('save_bunch.html', tags=tags)

    if request.form['save'] == '2':
        tags = request.form.getlist('tags')
        name = request.form['name']

        bunch = Bunches(current_user.id, name)
        db.session.commit()

        for tag in tags:
            bunch_tags = BunchTags(bunch.id, tag.id)

@app.route('/authors')
@login_required
def authors():
    ''' Display all authors for user's documents. '''

    authors = get_user_authors()
    return render_template('authors.html', authors=authors)

@app.route('/deauthorize', methods=['GET', 'POST'])
@login_required
def deauthorize():
    ''' Deauthorize a service and remove all docs from user's WYR account. '''
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

@app.route('/refresh')
@login_required
def refresh():
    ''' Manually refresh docs from a service. '''
    if request.args.get('name') == 'Mendeley':
        if current_user.mendeley == 1:
            update_mendeley()
            return render_template('settings.html')
    if request.args.get('name') == 'Goodreads':
        if current_user.goodreads == 1:
            update_goodreads()
            return render_template('settings.html')

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



################################################################################
################################################################################
### MENDELEY ###################################################################
# uses Oauth 2, returns json
# uses requests-oauthlib: https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow
# mendely documentation: http://dev.mendeley.com/reference/topics/authorization_overview.html
# service_id = 1
# to do: turn much of this code into functions

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

    mendeley = OAuth2Session(m['client_id'], state=session['oauth_state'], redirect_uri=m['redirect_uri'])
    token = mendeley.fetch_token(m['token_url'], code=code, username=m['client_id'], password=m['client_secret'])

    #save token in Tokens table
    tokens = Tokens(user_id=current_user.id, service_id=1, access_token=token['access_token'], refresh_token=token['refresh_token'])
    db.session.add(tokens)
    db.session.commit()

    return store_mendeley()

#gets doc info from mendeley and stores in database (only once, after initial authorization of service)
def store_mendeley():
    #get tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, service_id=1).first()

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
        #skip items not read
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

        if 'tags' in doc:
            tags = doc['tags']

            #get user's existing tags to check if tags for this doc already exist
            user_tags = get_user_tags()

            #append any user's existing tags to the document, remove from list tags
            for sublist in user_tags:
                for tag in tags[:]:
                    if sublist['name'] == tag:
                        #get the tag object and append to new_doc.tags
                        existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                        new_doc.tags.append(existing_tag)
                        #now remove it, so we don't create a new tag object below
                        tags.remove(tag)

            #any tag left in tags list will be a new one that needs to be created
            #create new tag objects for new tags, append to the doc
            for tag in tags:
                new_tag = Tags(tag)
                new_doc.tags.append(new_tag)

        if 'authors' in doc:
            authors = doc['authors']

            #get user's existing authors to check if authors for this doc already exist
            user_authors = get_user_authors()

            #append any of user's exsting authors to document, remove from list authors
            for sublist in user_authors:
                for author in authors[:]:
                    #if there's only one name, author[1] will through index error,
                    #but must try to match both first_name and last_name first
                    try:
                        if sublist['first_name'] == author['first_name'] and sublist['last_name'] == author['last_name']:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            new_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)
                    except KeyError:
                        if sublist['last_name'] == author['last_name']:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            new_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)

            #any author left in authors list will be a new one that needs to be created and appended to new_doc
            for author in authors:
                try:
                    new_author = Authors(author['first_name'], author['last_name'])
                except KeyError:
                    new_author = Authors(first_name='', last_name=author['last_name'])

                new_doc.authors.append(new_author)

        """
        #old
        if 'authors' in doc:
            for author in doc['authors']:
                try:
                    new_author = Authors(author['first_name'], author['last_name'], 0)
                except KeyError:
                    try:
                        new_author = Authors('', author['last_name'], 0)
                    except KeyError:
                        new_author = Authors(author['first_name'], '', 0)
                db.session.add(new_author)
        """
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
    #get existing tokens from Tokens table
    tokens = Tokens.query.filter_by(user_id=current_user.id, service_id=1).first()

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
        flash("There is a problem with your Mendeley authorization. Please contact me for help.")
        return redirect(url_for('settings'))

    #resave
    tokens.access_token = new_token['access_token']
    tokens.refresh_token = new_token['refresh_token']
    db.session.commit()

    #get new 0auth object with new token
    mendeley = OAuth2Session(m['client_id'], token=new_token)

    #parameters
    payload = {'limit':'500', 'view':'all'}

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

    #create a list of ids only, to use for removing deleted Mendeley docs later
    m_doc_ids = []

    # go through each doc, and see if we need to insert or update it
    for doc in m_docs:
        m_doc_ids.append(doc['id'])

        #skip items not read
        if doc['read'] == 0:
            continue

        #see if it's in the db
        check_doc = Documents.query.filter_by(user_id=current_user.id, service_id=1, native_doc_id=doc['id']).first()

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

            #add tags
            if 'tags' in doc:
                tags = doc['tags']

                #get user's existing tags to check if tags for this doc already exist
                user_tags = get_user_tags()

                #append any user's existing tags to the document, remove from list tags
                for sublist in user_tags:
                    for tag in tags[:]:
                        if sublist['name'] == tag:
                            #get the tag object and append to new_doc.tags
                            existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                            new_doc.tags.append(existing_tag)
                            #now remove it, so we don't create a new tag object below
                            tags.remove(tag)

                #any tag left in tags list will be a new one that needs to be created
                #create new tag objects for new tags, append to the doc
                for tag in tags:
                    new_tag = Tags(tag)
                    new_doc.tags.append(new_tag)

            if 'authors' in doc:
                authors = doc['authors']

                #get user's existing authors to check if authors for this doc already exist
                user_authors = get_user_authors()

                #append any of user's exsting authors to document, remove from list authors
                for sublist in user_authors:
                    for author in authors[:]:
                        #if there's only one name, author[1] will through index error,
                        #but must try to match both first_name and last_name first
                        try:
                            if sublist['first_name'] == author[1] and sublist['last_name'] == author[0]:
                                #get the author object and append to new_doc.authors
                                existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                new_doc.authors.append(existing_author)
                                #now remove it, so we don't create a new author object below
                                authors.remove(author)
                        except KeyError:
                            if sublist['last_name'] == author[0]:
                                #get the author object and append to new_doc.authors
                                existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                new_doc.authors.append(existing_author)
                                #now remove it, so we don't create a new author object below
                                authors.remove(author)

                #any author left in authors list will be a new one that needs to be created and appended to new_doc
                for author in authors:
                    try:
                        new_author = Authors(author[1], author[0])
                    except KeyError:
                        new_author = Authors(first_name='', last_name=author[0])

                    new_doc.authors.append(new_author)

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
            # first get tags, authors, and files from doc in db to check against updated doc
            old_tags = check_doc.tags
            old_authors = check_doc.authors
            old_file_links = check_doc.file_links

            # if it doesn't have 'last_modified' then it would have already been
            # caught by insert above, so skip rest of the loop
            if not doc['last_modified']:
                continue

            # if it does have last_modified, convert it to datetime object and check if newer than one in db
            # (no need to update if not)
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

                # update tags
                # one scenario not caught by "if tags:" below: there were old tags, but no
                # new tags (user deleted one/all). Have to treat this separately.
                if old_tags and not 'tags' in doc:
                    for old_tag in old_tags:
                        check_doc.tags.remove(old_tag)

                if 'tags' in doc:
                    tags = doc['tags']

                    # check old tag list against tags submitted after edit, remove any no longer there
                    if old_tags:

                        # remove it from doc's tags if necessary
                        ################################################################
                        # to do
                        # one issue with this: doesn't delete an orphaned tag from tags table
                        # I'm not sure if I need to do this manually or better configure relationships
                        ###############################################################

                        for old_tag in old_tags[:]:
                            if old_tag not in tags:
                                check_doc.tags.remove(tag)

                        #don't add tags if they were already in old_tags - would be a duplicate
                        for tag in tags[:]:
                            if tag in old_tags:
                                tags.remove(tag)

                    #get user's existing tags to check if tags for this doc already exist
                    user_tags = get_user_tags()

                    #append any user's existing tags to the document, remove from list tags
                    for sublist in user_tags:
                        for tag in tags[:]:
                            if sublist['name'] == tag:
                                #get the tag object and append to new_doc.tags
                                existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                                check_doc.tags.append(existing_tag)
                                #now remove it, so we don't create a new tag object below
                                tags.remove(tag)

                    #any tag left in tags list will be a new one that needs to be created
                    #create new tag objects for new tags, append to the doc
                    for tag in tags:
                        new_tag = Tags(tag)
                        check_doc.tags.append(new_tag)

                # update authors
                # one scenario not caught by "if authors:" below: there were old authors, but no
                # new authors (user deleted one/all). Have to treat this separately.
                if old_authors and not 'authors' in doc:
                    for old_author in old_authors[:]:
                        check_doc.authors.remove(old_author)

                if 'authors' in doc:
                    authors = doc['authors']

                    # check old author list of lists against authors submitted after edit, remove any no longer there
                    if old_authors:

                    # remove it from doc's authors if necessary
                    ################################################################
                    # to do
                    # one issue with this: doesn't delete an orphaned author
                    # I'm not sure if I need to do this manually or better configure relationships
                    ################################################################

                        for old_author in old_authors[:]:
                            if old_author not in authors:
                                check_doc.authors.remove(old_author)

                        #don't add authors if they were already in old_authors - would be a duplicate
                        for author in authors[:]:
                            if author in old_authors:
                                authors.remove(author)

                    #get user's existing authors to check if authors for this doc already exist
                    user_authors = get_user_authors()

                    #append any of user's exsting authors to document, remove from list authors
                    for sublist in user_authors:
                        for author in authors[:]:
                            #if there's only one name, author[1] will through index error,
                            #but must try to match both first_name and last_name first
                            try:
                                if sublist['first_name'] == author['first_name'] and sublist['last_name'] == author['last_name']:
                                    #get the author object and append to new_doc.authors
                                    existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                    check_doc.authors.append(existing_author)
                                    #now remove it, so we don't create a new author object below
                                    authors.remove(author)
                            except KeyError:
                                if sublist['last_name'] == author['last_name']:
                                    #get the author object and append to new_doc.authors
                                    existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                    check_doc.authors.append(existing_author)
                                    #now remove it, so we don't create a new author object below
                                    authors.remove(author)

                    #any author left in authors list will be a new one that needs to be created and appended to new_doc
                    for author in authors:
                        try:
                            new_author = Authors(author['first_name'], author['last_name'])
                        except KeyError:
                            new_author = Authors(first_name='', last_name=author['last_name'])

                        check_doc.authors.append(new_author)

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


    #now remove any deleted docs
    #first, get docs in db
    docs = db.session.query(Documents.native_doc_id).filter_by(user_id=current_user.id, service_id=1).all()

    #if doc.native_doc_id is not in m_doc_ids, delete it
    for doc in docs:
        if doc.native_doc_id not in m_doc_ids:
            Documents.query.filter_by(user_id=current_user.id, service_id=1, native_doc_id=doc.native_doc_id).delete()

    current_user.mendeley_update = datetime.now()
    db.session.commit()

    flash('Documents from Mendeley have been refreshed.')
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
        link = request.args.get('link', '')

        #also pass along tags and author names for autocomplete
        tags = get_user_tag_names()
        authors = get_user_author_names()

        #check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.service_id==3).count() >= 1:
                doc = current_user.documents.filter(Documents.link==link, Documents.service_id==3).first()
                flash("You've already saved that link; you may edit it below.")
                return redirect(url_for('edit', id=doc.id))

        return render_template('add.html', title=title, link=link, tags=tags, authors=authors)

    elif request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        year = request.form['year']
        tags = request.form['tags']
        authors = request.form['authors']
        notes = request.form['notes'].replace('\n', '<br>')
        submit = request.form['submit']

        #validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return redirect(url_for('add'))

        #check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.service_id==3).count() >= 1:
                doc = current_user.documents.filter_by(Documents.link==link, Documents.service_id==3).first()
                flash("You've already saved that link; you may edit it below.")
                return redirect(url_for('edit', id=doc.id))

        #insert
        new_doc = Documents(3, title)
        current_user.documents.append(new_doc)

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

        if tags:
            #cleanup into list of tags
            tags = str_tags_to_list(tags)

            #get user's existing tags to check if tags for this doc already exist
            user_tags = get_user_tags()

            #append any user's existing tags to the document, remove from list tags
            for sublist in user_tags:
                for tag in tags[:]:
                    if sublist['name'] == tag:
                        #get the tag object and append to new_doc.tags
                        existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                        new_doc.tags.append(existing_tag)
                        #now remove it, so we don't create a new tag object below
                        tags.remove(tag)

            #any tag left in tags list will be a new one that needs to be created
            #create new tag objects for new tags, append to the doc
            for tag in tags:
                new_tag = Tags(tag)
                new_doc.tags.append(new_tag)

        if authors:
            #cleanup into list of list of authors
            authors = str_authors_to_list(authors)

            #get user's existing authors to check if authors for this doc already exist
            user_authors = get_user_authors()

            #append any of user's exsting authors to document, remove from list authors
            for sublist in user_authors:
                for author in authors[:]:
                    #if there's only one name, author[1] will through index error,
                    #but must try to match both first_name and last_name first
                    try:
                        if sublist['first_name'] == author[1] and sublist['last_name'] == author[0]:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            new_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)
                    except IndexError:
                        if sublist['last_name'] == author[0]:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            new_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)

            #any author left in authors list will be a new one that needs to be created and appended to new_doc
            for author in authors:
                try:
                    new_author = Authors(author[1], author[0])
                except IndexError:
                    new_author = Authors(first_name='', last_name=author[0])

                new_doc.authors.append(new_author)


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

        doc = current_user.documents.filter(Documents.id==id).first()

        if doc:

            new_tags = ''
            new_authors_list = []
            new_authors = ''

            #have to format tags and authors for form
            if doc.tags:
                #put names into list to sort
                super_new_tag_list=[tag.name for tag in doc.tags]
                super_new_tag_list.sort() #sort
                for name in super_new_tag_list:
                    if name != super_new_tag_list[-1]:
                        new_tags += name + ', '
                    else:
                        new_tags += name

            if doc.authors:
                for author in doc.authors:
                    new_authors_list.append(author)


            for author in new_authors_list:
                if author != new_authors_list[-1]:
                    new_authors += author.last_name + ', ' + author.first_name + '; '
                else:
                    new_authors += author.last_name + ', ' + author.first_name

            #also pass along all tags for autocomplete
            all_tags = get_user_tag_names()

            #also pass along all authors for autocomplete
            all_authors = get_user_author_names()

            #took out all_tags=all_tags from below to see if it would work
            return render_template('edit.html', doc=doc, tags=new_tags, all_tags=all_tags, all_authors=all_authors, authors=new_authors)
        else:
            return redirect(url_for('index'))

    elif request.method == 'POST':
        id = request.form['id']
        title = request.form['title']
        link = request.form['link']
        year = request.form['year']
        tags = request.form['tags']
        old_tags = request.form['old_tags']
        authors = request.form['authors']
        old_authors = request.form['old_authors']
        notes = request.form['notes'].replace('\n', '<br>')
        tagpage = request.form['tagpage']
        authorpage = request.form['authorpage']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        submit = request.form['submit']

        if submit == "Cancel":
            flash("Edit canceled.")
            if tagpage != 'None':
                return redirect(url_for('docs_by_tag', tag=tagpage))
            elif authorpage != 'None':
                return redirect(url_for('docs_by_author', first_name=first_name, last_name=last_name))
            else:
                return redirect(url_for('index'))

        #validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return redirect(url_for('edit'))

        #update
        update_doc = current_user.documents.filter(Documents.service_id==3, Documents.id==id).first()

        update_doc.title = title

        #add http:// if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        update_doc.link = link
        update_doc.year = year
        update_doc.note = notes
        update_doc.last_modified = datetime.now()


        # one scenario not caught by "if tags:" below: there were old tags, but no
        # new tags (user deleted one/all). Have to treat this separately.
        if old_tags and not tags:
            old_tags = str_tags_to_list(old_tags)
            for old_tag in old_tags[:]:
                #to get the right tag to remove, loop through all and match by name
                for tag in update_doc.tags[:]:
                    if tag.name == old_tag:
                        update_doc.tags.remove(tag)

        if tags:
            #cleanup into list of tags
            tags = str_tags_to_list(tags)

            # check old tag list against tags submitted after edit, remove any no longer there
            if old_tags:
                # get old tags
                old_tags = str_tags_to_list(old_tags)


                # remove it from doc's tags if necessary
                ################################################################
                # to do
                # one issue with this: doesn't delete an orphaned tag from tags table
                # I'm not sure if I need to do this manually or better configure relationships
                ###############################################################
                for old_tag in old_tags[:]:
                    if old_tag not in tags:
                        #to get the right tag to remove, loop through all and match by name
                        for tag in update_doc.tags[:]:
                            if tag.name == old_tag:
                                update_doc.tags.remove(tag)



                #don't add tags if they were already in old_tags - would be a duplicate
                for tag in tags[:]:
                    if tag in old_tags:
                        tags.remove(tag)


            #get user's existing tags to check if tags for this doc already exist
            user_tags = get_user_tags()

            #append any user's existing tags to the document, remove from list tags
            for sublist in user_tags:
                for tag in tags[:]:
                    if sublist['name'] == tag:
                        #get the tag object and append to new_doc.tags
                        existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                        update_doc.tags.append(existing_tag)
                        #now remove it, so we don't create a new tag object below
                        tags.remove(tag)

            #any tag left in tags list will be a new one that needs to be created
            #create new tag objects for new tags, append to the doc
            for tag in tags:
                new_tag = Tags(tag)
                update_doc.tags.append(new_tag)


        # one scenario not caught by "if authors:" below: there were old authors, but no
        # new authors (user deleted one/all). Have to treat this separately.
        if old_authors and not authors:
            old_authors = str_authors_to_list(old_authors)
            for old_author in old_authors[:]:
                #to get the right author to remove, loop through all and match by name
                for author in update_doc.authors[:]:
                    if author.first_name == old_author[1] and author.last_name == old_author[0]:
                        update_doc.authors.remove(author)

        if authors:
            #cleanup into list of lists
            authors = str_authors_to_list(authors)

            # check old author list of lists against authors submitted after edit, remove any no longer there
            if old_authors:
                # get old tags
                old_authors = str_authors_to_list(old_authors)

                # remove it from doc's authors if necessary
                ################################################################
                # to do
                # one issue with this: doesn't delete an orphaned author
                # I'm not sure if I need to do this manually or better configure relationships
                ################################################################
                for old_author in old_authors[:]:
                    if old_author not in authors:
                        #to get the right author to remove, loop through all and match by name
                        for author in update_doc.authors[:]:
                            if author.first_name == old_author[1] and author.last_name == old_author[0]:
                                update_doc.authors.remove(author)

                #don't add authors if they were already in old_authors - would be a duplicate
                for author in authors[:]:
                    if author in old_authors:
                        authors.remove(author)

            #get user's existing authors to check if authors for this doc already exist
            user_authors = get_user_authors()

            #append any of user's exsting authors to document, remove from list authors
            for sublist in user_authors:
                for author in authors[:]:
                    #if there's only one name, author[1] will through index error,
                    #but must try to match both first_name and last_name first
                    try:
                        if sublist['first_name'] == author[1] and sublist['last_name'] == author[0]:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            update_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)
                    except IndexError:
                        if sublist['last_name'] == author[0]:
                            #get the author object and append to new_doc.authors
                            existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                            update_doc.authors.append(existing_author)
                            #now remove it, so we don't create a new author object below
                            authors.remove(author)

            #any author left in authors list will be a new one that needs to be created and appended to new_doc
            for author in authors:
                try:
                    new_author = Authors(author[1], author[0])
                except IndexError:
                    new_author = Authors(first_name='', last_name=author[0])

                update_doc.authors.append(new_author)

        #remove orphaned tags
        #auto_delete_orphans(Documents.tags)

        #remove orphaned authors
        #auto_delete_orphans(Documents.authors)

        db.session.commit()
        flash('Item edited.')
        if tagpage != 'None':
            return redirect(url_for('docs_by_tag', tag=tagpage))
        if authorpage != 'None':
            return redirect(url_for('docs_by_author', first_name=first_name, last_name=last_name))
        return redirect(url_for('index'))

    else:
        return redirect(url_for('index'))

@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        #check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = current_user.documents.filter(Documents.id==id, Documents.service_id==3).first()
        if doc:
            return render_template('delete.html', doc=doc)
        else:
            return redirect(url_for('index'))
    elif request.method == 'POST':
        delete = request.form['delete']
        id = request.form['id']
        if delete == 'Delete':
            #delete doc
            doc = current_user.documents.filter(Documents.id==id, Documents.service_id==3).one()

            #delete docs tags
            for tag in doc.tags:
                doc.tags.remove(tag)

            #delete docs authors
            for author in doc.authors:
                doc.authors.remove(author)

            #delete it
            doc = current_user.documents.filter(Documents.id==id, Documents.service_id==3).delete()

            db.session.commit()
            flash("Item deleted.")
            return redirect(url_for('index'))
        if delete == 'Cancel':
            flash("Item not deleted.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/tags/edit', methods=['GET', 'POST'])
@login_required
def bulk_edit():
    if request.method == 'GET':
        #display tags just like in /tags, but only for native docs
        #tags = db.session.query(Tags.name).filter_by(user_id=current_user.id, service_id="3").order_by(Tags.name).distinct()
        tags = db.session.query(Tags.name).join(Documents).filter(Documents.user_id==current_user.id, Documents.service_id=="3").\
        order_by(Tags.name).distinct()

        #form names can't contain spaces, so have to work around - send dict of tag names, temp_ids
        tag_list = list()
        i=0
        for tag in tags:
            tag_list.append({'temp_id':i, 'name':tag.name})
            i += 1

        return render_template('edit_tags.html', tags=tag_list)

    else:
        return render_template('contact.html')
        """
        if request.form['submit'] == 'Cancel':
            return redirect(url_for('tags'))


        form_variables = request.form
        #go through each one starting with "rename." or "delete." and rename/delete?

        #original dict is in input tag_list, has temp_ids and names, use to associate with rename.#/delete.#

        return render_template('test_bulk_edit.html', variables=form_variables)
        """


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
            new_doc = Documents(2, doc.find('book/title').text)
            current_user.documents.append(new_doc)
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

            """
            old
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
            """
            if doc.find('shelves/shelf') is not None:
                #make list of tags from shelves, to make adding new or existing tags easier
                tags = []
                for shelf in doc.findall('shelves/shelf'):
                #these are all in 'read' shelf, don't add that as a tag
                    if shelf.get('name') == 'read':
                        continue
                    tags.append(shelf.get('name'))

                #get user's existing tags to check if tags for this doc already exist
                user_tags = get_user_tags()

                #append any user's existing tags to the document, remove from list tags
                for sublist in user_tags:
                    # loop through all book's shelves and add
                    for tag in tags:
                        #if already a tag, don't add new one,
                        if sublist['name'] == tag:
                            #get the tag object and append to new_doc.tags
                            existing_tag = Tags.query.filter(Tags.id==sublist['id']).one()
                            new_doc.tags.append(existing_tag)
                            #now remove it, so we don't create a new tag object below
                            tags.remove(tag)

                #any tag left in tags list will be a new one that needs to be created
                #create new tag objects for new tags, append to the doc
                for tag in tags:
                    new_tag = Tags(tag)
                    new_doc.tags.append(new_tag)


            if doc.find('book/authors/author/name') is not None:
                #create list of authors
                authors = []
                for name in doc.findall('book/authors/author/name'):
                    #split one full name into first and last (jr's don't work right now #to do)
                    new_name = name.text.rsplit(' ', 1)
                    authors.append([new_name[0], new_name[1]])


                #get user's existing authors to check if authors for this doc already exist
                user_authors = get_user_authors()

                #append any of user's exsting authors to document, remove from list authors
                for sublist in user_authors:
                    for author in authors[:]:
                        #if there's only one name, author[1] will through index error,
                        #but must try to match both first_name and last_name first
                        try:
                            if sublist['first_name'] == author[1] and sublist['last_name'] == author[0]:
                                #get the author object and append to new_doc.authors
                                existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                new_doc.authors.append(existing_author)
                                #now remove it, so we don't create a new author object below
                                authors.remove(author)
                        except IndexError:
                            if sublist['last_name'] == author[0]:
                                #get the author object and append to new_doc.authors
                                existing_author = Authors.query.filter(Authors.id==sublist['id']).one()
                                new_doc.authors.append(existing_author)
                                #now remove it, so we don't create a new author object below
                                authors.remove(author)

                #any author left in authors list will be a new one that needs to be created and appended to new_doc
                for author in authors:
                    try:
                        new_author = Authors(author[1], author[0])
                    except IndexError:
                        new_author = Authors(first_name='', last_name=author[0])

                    new_doc.authors.append(new_author)


        db.session.commit()

        i += 1

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

    flash('Documents from Goodreads have been refreshed.')

    return

################################################################################
################################################################################
## IMPORT BOOKMARKS FROM HTML FILE #############################################
# also service_id 3

from bs4 import BeautifulSoup

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_bookmarks():
    if request.method == 'POST':
        #get folders so user can select which ones to import
        if 'step1' in request.form:

            if request.form['step1'] == "Cancel":
                flash("Bookmarks import cancelled.")
                return redirect(url_for('settings'))

            #get file and return user to form if none selected
            file = request.files['bookmarks']

            #limit size of file
            #except RequestEntityTooLarge:
            #    flash('Sorry, that file is a bit too big.')
            #    return render_template('import.html')


            if not file:
                flash('No file was selected. Please choose a file.')
                return render_template('import.html')

            #get file extension and return user to form if not .html
            file_extension = file.filename.rsplit('.', 1)[1]
            if file_extension != 'html':
                flash("Sorry, that doesn't look like a .html file.")
                return render_template('import.html')

            #limit size of file

            #make object global to get it again, parse file for folders
            global soup
            soup = BeautifulSoup(file, 'html.parser')
            folders = []
            for each in soup.find_all('h3'):
                folders.append(each.string)

            #return user to import to choose which folders to pull links from
            return render_template('import.html', step2='yes', folders=folders)

        #import bookmarks and their most immediate folder into db
        if 'step2' in request.form:

            if request.form['step2'] == 'Cancel':
                flash("Bookmarks import cancelled.")
                return redirect(url_for('settings'))

            #put checked folders into list
            folders = request.form.getlist('folder')

            global soup

            for each in soup.find_all('a'):
                if each.string != None:
                    # get the dl above the link
                    parent_dl = each.find_parent('dl')
                    # get the dt above that
                    grandparent_dt = parent_dl.find_parent('dt')
                    if grandparent_dt != None:
                        #get the h3 below the grandparent dt
                        h3 = grandparent_dt.find_next('h3')
                        #check that there is a folder and that it's in user-reviewed list
                        if h3 != None:
                            if h3.string in folders:
                                #replace commas with spaces in folders before inserting into db
                                h3.string = h3.string.replace(',', '')
                                new_doc = Documents(current_user.id, 3, each.string)
                                new_doc.link = each['href']
                                new_doc.read = 1
                                #convert add_date (seconds from epoch format) to datetime
                                new_doc.created = datetime.fromtimestamp(int(each['add_date']))
                                db.session.add(new_doc)
                                db.session.commit()
                                new_tag = Tags(current_user.id, new_doc.id, h3.string)
                                db.session.add(new_tag)
                                db.session.commit()

            flash('Bookmarks successfully imported.')
            return redirect(url_for('index'))

    return render_template('import.html')



