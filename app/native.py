from collections import namedtuple
import datetime
import pytz

from bs4 import BeautifulSoup
from flask import Blueprint, render_template, request, redirect, url_for, \
    flash, session
from flask_login import login_required, current_user

from app import db
from .models import Documents
from . import common
from . import exceptions as ex


native_bp = Blueprint('native', __name__)

############
# WYR NATIVE
# source_id = 3

def return_to_previous():
    ''' redirect user back to last page prior to edit or delete (or cancel) '''

    if 'return_to' in session:
        return redirect(session['return_to'])
    return redirect(url_for('main.index'))


@native_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'GET':

        # although only 2 vars may be populated, create full object bc this
        # goes to same template as editing doc and will reduce if/else in temp
        title = request.args.get('title', '')
        link = request.args.get('link', '')
        from_bookmarklet = request.args.get('bookmarklet', '')

        # because add() and edit() go to same template, create namedtuple for ease of use
        doc = namedtuple('doc', ['title', 'link', 'year', 'note'])
        doc.title = title
        doc.link = link
        doc.year, doc.note, tags, authors = '', '', '', ''

        # also pass along tags and author names for autocomplete
        all_tags = common.get_user_tags(current_user)
        all_tags = [tag.name for tag in all_tags]
        all_authors = common.get_user_authors(current_user)
        all_authors = [author.last_name + ', ' + author.first_name for author in all_authors]

        # check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.source_id==3).count() >= 1:
                doc = current_user.documents.filter(Documents.link==link, Documents.source_id==3).first()
                read_type = 'read' if doc.read == 1 else 'to-read'

                flash(f"You've already saved that link as {read_type}; "
                    "you may edit it below.")
                return redirect(url_for('native.edit', id=doc.id))

        return render_template('add.html', doc=doc, tags=tags, authors=authors,
            all_tags=all_tags, all_authors=all_authors,
            from_bookmarklet=from_bookmarklet)

    elif request.method == 'POST':

        content = request.form  # ImmutableDict, but functions much in the same way as json

        try:
            common.add_item(content, current_user)
        except ex.NoTitleException as e:
            flash(e.message)
            return redirect(url_for('native.add'))
        except ex.DuplicateLinkException as e:
            flash(e.message)
            return redirect(url_for('native.edit', id=e.doc_id))

        flash('Item added.')

        if content.get('from_bookmarklet'):
            return render_template('add.html', bookmarklet=1)

        if content.get('another'):
            return redirect(url_for('native.add'))

        return redirect(url_for('main.index'))
    else:
        return redirect(url_for('main.index'))


@native_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    if request.method == 'GET':
        # check that doc is one of current_user's
        id = request.args.get('id', '')

        doc = current_user.documents.filter(Documents.id==id).first()

        if doc:
            new_tags = ''
            new_authors_list = []
            new_authors = ''

            # have to format tags and authors for form
            if doc.tags:
                # put names into list to sort
                super_new_tag_list=[tag.name for tag in doc.tags]
                super_new_tag_list.sort() # sort
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

            # also pass along all tags and authors for autocomplete
            all_tags = common.get_user_tags(current_user)
            all_tags = [tag.name for tag in all_tags]
            all_authors = common.get_user_authors(current_user)
            all_authors = [author.last_name + ', ' + author.first_name for author in all_authors]

            return render_template('add.html', edit=1, doc=doc, tags=new_tags,
                all_tags=all_tags, all_authors=all_authors, authors=new_authors)
        else:
            return redirect(url_for('main.index'))

    elif request.method == 'POST':

        content = request.form

        try:
            common.edit_item(content, current_user)
        except ex.NoTitleException as e:
            flash(e.message)
            return redirect(url_for('native.edit', id=e.doc_id))
        except ex.DuplicateLinkException as e:
            flash(e.message)
            return redirect(url_for('native.edit', id=e.doc_id))

        flash('Item edited.')

        return return_to_previous()

    else:
        return redirect(url_for('main.index'))

@native_bp.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        # check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).first()

        if doc:
            read_status = 'to-read' if doc.read == 0 else 'read'

            return render_template('delete.html', doc=doc, read_status=read_status)
        else:
            return redirect(url_for('main.index'))
    elif request.method == 'POST':
        delete = request.form['delete']
        id = request.form['id']
        if delete == 'Cancel':
            flash("Item not deleted.")
            return return_to_previous()

        if delete == 'Delete':
            # delete doc
            doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).one()

            # delete docs tags
            for tag in doc.tags[:]:
                doc.tags.remove(tag)

            # delete docs authors
            for author in doc.authors[:]:
                doc.authors.remove(author)

            # delete it
            doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).delete()

            db.session.commit()
            flash("Item deleted.")
            return return_to_previous()

    else:
        return redirect(url_for('main.index'))

@native_bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_bookmarks():
    '''Import bookmarks from HTML file.'''

    if request.method == 'POST':
        # get folders so user can select which ones to import
        if 'step1' in request.form:

            if request.form['step1'] == "Cancel":
                flash("Bookmarks import cancelled.")
                return redirect(url_for('main.settings'))

            # get file and return user to form if none selected
            file = request.files['bookmarks']

            if not file:
                flash('No file was selected. Please choose a file.')
                return render_template('import.html')

            # get file extension and return user to form if not .html
            file_extension = file.filename.rsplit('.', 1)[1]
            if file_extension != 'html':
                flash("Sorry, that doesn't look like a .html file.")
                return render_template('import.html')


            # put soupped file into a global variable accessed by username,
            # so we can work with it after step 2 (and so it's uniquely named)
            global soup
            soup = dict()
            soup[current_user.username] = BeautifulSoup(file, 'html.parser')
            folders = []
            for each in soup[current_user.username].find_all('h3'):
                folders.append(each.string)

            #return user to import to choose which folders to pull links from
            return render_template('import.html', step2='yes', folders=folders)

        #import bookmarks and their most immediate folder into db
        if 'step2' in request.form:

            if request.form['step2'] == 'Cancel':
                flash("Bookmarks import cancelled.")
                return redirect(url_for('main.settings'))

            # put checked folders into list
            folders = request.form.getlist('folder')

            for each in soup[current_user.username].find_all('a'):
                if each.string != None:
                    # get the dl above the link
                    parent_dl = each.find_parent('dl')
                    # get the dt above that
                    grandparent_dt = parent_dl.find_parent('dt')
                    if grandparent_dt != None:
                        # get the h3 below the grandparent dt
                        h3 = grandparent_dt.find_next('h3')
                        # check that there is a folder and that it's in user-reviewed list
                        if h3 != None:
                            if h3.string in folders:
                                # replace commas with spaces in folders before inserting into db
                                h3.string = h3.string.replace(',', '')
                                new_doc = Documents(3, each.string)
                                current_user.documents.append(new_doc)
                                new_doc.link = each['href']
                                new_doc.read = 1
                                # convert add_date (seconds from epoch format) to datetime
                                new_doc.created = datetime.datetime.fromtimestamp(int(each['add_date']))
                                db.session.add(new_doc)
                                db.session.commit()
                                common.add_tags_to_doc(current_user, [h3.string], new_doc)
                                db.session.commit()

            flash('Bookmarks successfully imported.')
            return redirect(url_for('main.index'))

    return render_template('import.html')

