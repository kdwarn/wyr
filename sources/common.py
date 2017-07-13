from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask.ext.login import login_required, current_user
from app import db
from sources.mendeley import import_mendeley
from sources.goodreads import import_goodreads
from models import Documents, Tokens

common_blueprint = Blueprint('common', __name__, template_folder='templates')

############################
### COMMON SOURCE ROUTES ###
############################

# verification from authorizing a source, storing of initial data
@common_blueprint.route('/authorized/<source>', methods=['GET', 'POST'])
@login_required
def verify_authorization(source):
    if request.method == 'GET':
        return render_template('verify_and_store.html', source=source)
    elif request.method == 'POST':
        if source == 'Mendeley':
            current_user.include_m_unread = request.form['include_m_unread']
            db.session.commit()
            import_mendeley('initial')

        if source == 'Goodreads':
            current_user.include_g_unread = request.form['include_g_unread']
            db.session.commit()
            import_goodreads('initial')

        return redirect(url_for('index'))

    else:
        return redirect(url_for('index'))

@common_blueprint.route('/deauthorize', methods=['GET', 'POST'])
@login_required
def deauthorize():
    ''' Deauthorize a source and remove all docs from user's WYR account. '''
    if request.method == 'GET':
        return render_template('deauthorize.html', name=request.args.get('name'))
    elif request.method == 'POST':
        #what are they trying to deauthorize?
        source = request.form['name']
        confirm = request.form['deauthorize']
        if confirm == 'Yes':
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
                #unset my flags for this
                current_user.goodreads = 0
                current_user.goodreads_update = 'NULL'
                current_user.include_g_unread = 0

            message = '{} has been deauthorized.'.format(source)
            db.session.commit()
        else:
            message = 'Deauthorization cancelled.'

        flash(message)
        return redirect(url_for('settings'))
    else:
        return redirect(url_for('index'))

@common_blueprint.route('/refresh')
@login_required
def refresh():
    ''' Manually refresh docs from a source.
        A user could skip doing the import of items immediately after
        authorizing by going to home page, so there's a check in for that.
    '''
    if request.args.get('name') == 'Mendeley':
        if current_user.mendeley == 1:
            if current_user.mendeley_update:
                import_mendeley('normal')
            else:
                import_mendeley('initial')
            return render_template('settings.html')
    if request.args.get('name') == 'Goodreads':
        if current_user.goodreads == 1:
            if current_user.goodreads_update:
                import_goodreads('normal')
            else:
                import_mendeley('initial')
            return render_template('settings.html')

