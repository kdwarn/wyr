from flask import Blueprint, render_template, request, redirect, url_for, \
    flash, session
from flask.ext.login import login_required, current_user
from datetime import datetime
from db_functions import get_user_tag_names, get_user_author_names, \
    str_tags_to_list, add_tags_to_doc, remove_old_tags,  \
    str_authors_to_list, add_authors_to_doc, remove_old_authors
from bs4 import BeautifulSoup
import pytz

from app import db
from models import Documents


native_blueprint = Blueprint('native', __name__, template_folder='templates')

############
# WYR NATIVE
# source_id = 3

def return_to_previous():
    ''' redirect user back to last page prior to edit or delete (or cancel) '''

    if 'return_to' in session:
        return redirect(session['return_to'])
    return redirect(url_for('index'))

@native_blueprint.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'GET':

        # if this is from bookmarklet, pass along variables
        title = request.args.get('title')
        link = request.args.get('link', '')

        # also pass along tags and author names for autocomplete
        tags = get_user_tag_names()
        authors = get_user_author_names()

        # check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.source_id==3).count() >= 1:
                doc = current_user.documents.filter(Documents.link==link, Documents.source_id==3).first()
                flash("You've already saved that link; you may edit it below.")
                return redirect(url_for('native.edit', id=doc.id))

        return render_template('add.html', title=title, link=link, tags=tags, authors=authors)

    elif request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        year = request.form['year']
        tags = request.form['tags']
        authors = request.form['authors']
        notes = request.form['notes']
        read = int(request.form['read'])
        submit = request.form['submit']

        # validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return redirect(url_for('native.add'))

        # check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.source_id==3).count() >= 1:
                doc = current_user.documents.filter_by(Documents.link==link, Documents.source_id==3).first()
                flash("You've already saved that link; you may edit it below.")
                return redirect(url_for('native.edit', id=doc.id))

        # insert
        new_doc = Documents(3, title)
        current_user.documents.append(new_doc)

        # add "http://" if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        new_doc.link = link
        new_doc.year = year
        new_doc.note = notes
        new_doc.read = read
        new_doc.created = datetime.now(pytz.utc)
        db.session.add(new_doc)

        if tags:
            tags = str_tags_to_list(tags)
            new_doc = add_tags_to_doc(tags, new_doc)

        if authors:
            authors = str_authors_to_list(authors)
            new_doc = add_authors_to_doc(authors, new_doc)

        db.session.commit()

        flash('Item added.')

        if submit == "Submit and Return Home":
            return redirect(url_for('index'))
        if submit == "Submit and Add Another":
            return redirect(url_for('native.add'))
        # if submitted from bookmarklet, just send to confirmation page
        if submit == "Submit":
            return render_template('add.html', bookmarklet=1)
    else:
        return redirect(url_for('index'))

@native_blueprint.route('/edit', methods=['GET', 'POST'])
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
            all_tags = get_user_tag_names()
            all_authors = get_user_author_names()

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
        notes = request.form['notes']
        read = int(request.form['read'])
        submit = request.form['submit']

        if submit == "Cancel":
            flash("Edit canceled.")
            return return_to_previous()

        # validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return redirect(url_for('native.edit'))

        # update
        update_doc = current_user.documents.filter(Documents.source_id==3, Documents.id==id).first()
        update_doc.title = title

        # add http:// if not there or else will be relative link within site
        if link:
            if 'http://' not in link and 'https://' not in link:
                link = 'http://' + link

        update_doc.link = link
        update_doc.year = year
        update_doc.note = notes

        # if change from to-read to read, updated created, delete last_modified
        if update_doc.read == 0 and read == 1:
            update_doc.created = datetime.now(pytz.utc)
            update_doc.last_modified = ''
        else:
            update_doc.last_modified = datetime.now(pytz.utc)

        update_doc.read = read


        # update tags
        # turn strings of tags into lists of tags
        tags = str_tags_to_list(tags)
        old_tags = str_tags_to_list(old_tags)
        # if there were old tags, remove those no longer associated with doc,
        # update the doc and also return updated list of tags
        if old_tags:
            update_doc, tags = remove_old_tags(old_tags, tags, update_doc)
        # add any new tags to doc
        if tags:
            update_doc = add_tags_to_doc(tags, update_doc)

        # update authors
        authors = str_authors_to_list(authors)
        old_authors = str_authors_to_list(old_authors)
        if old_authors:
            update_doc, authors = remove_old_authors(old_authors, authors,
                update_doc)
        if authors:
            update_doc = add_authors_to_doc(authors, update_doc)

        db.session.commit()
        flash('Item edited.')

        return return_to_previous()

    else:
        return redirect(url_for('index'))

@native_blueprint.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        # check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).first()

        if doc:
            if doc.read == 0:
                read_status = 'to-read'
            else:
                read_status = 'read'

            return render_template('delete.html', doc=doc, read_status=read_status)
        else:
            return redirect(url_for('index'))
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
            for tag in doc.tags:
                doc.tags.remove(tag)

            # delete docs authors
            for author in doc.authors:
                doc.authors.remove(author)

            # delete it
            doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).delete()

            db.session.commit()
            flash("Item deleted.")
            return return_to_previous()

    else:
        return redirect(url_for('index'))

@native_blueprint.route('/import', methods=['GET', 'POST'])
@login_required
def import_bookmarks():
    '''Import bookmarks from HTML file.'''

    if request.method == 'POST':
        # get folders so user can select which ones to import
        if 'step1' in request.form:

            if request.form['step1'] == "Cancel":
                flash("Bookmarks import cancelled.")
                return redirect(url_for('settings'))

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
            soup = dict()
            soup[current_user.username] = BeautifulSoup(file, 'html.parser')

            global soup

            folders = []
            for each in soup[current_user.username].find_all('h3'):
                folders.append(each.string)

            #return user to import to choose which folders to pull links from
            return render_template('import.html', step2='yes', folders=folders)

        #import bookmarks and their most immediate folder into db
        if 'step2' in request.form:

            if request.form['step2'] == 'Cancel':
                flash("Bookmarks import cancelled.")
                return redirect(url_for('settings'))

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
                                new_doc.created = datetime.fromtimestamp(int(each['add_date']))
                                db.session.add(new_doc)
                                db.session.commit()
                                add_tags_to_doc([h3.string], new_doc)
                                db.session.commit()

            flash('Bookmarks successfully imported.')
            return redirect(url_for('index'))

    return render_template('import.html')

