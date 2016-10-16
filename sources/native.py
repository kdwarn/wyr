from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask.ext.login import login_required, current_user
from datetime import datetime
from db_functions import get_user_tags, get_user_tag_names, get_user_authors, \
    get_user_author_names, str_tags_to_list, str_authors_to_list
from bs4 import BeautifulSoup
from app import db
from models import Documents, Tags, Authors

native_blueprint = Blueprint('native', __name__, template_folder='templates')

#
# WYR NATIVE
# source_id = 3

@native_blueprint.route('/add', methods=['GET', 'POST'])
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
        notes = request.form['notes'].replace('\n', '<br>')
        submit = request.form['submit']

        #validation
        if not title:
            flash('Please enter a title. It is the only required field.')
            return redirect(url_for('add'))

        #check if link already exists, redirect user to edit if so
        if link:
            if current_user.documents.filter(Documents.link==link, Documents.source_id==3).count() >= 1:
                doc = current_user.documents.filter_by(Documents.link==link, Documents.source_id==3).first()
                flash("You've already saved that link; you may edit it below.")
                return redirect(url_for('native.edit', id=doc.id))

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

@native_blueprint.route('/edit', methods=['GET', 'POST'])
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
            return redirect(url_for('native.edit'))

        #update
        update_doc = current_user.documents.filter(Documents.source_id==3, Documents.id==id).first()

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

@native_blueprint.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        #check that doc is one of current_user's
        id = request.args.get('id', '')
        doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).first()
        if doc:
            return render_template('delete.html', doc=doc)
        else:
            return redirect(url_for('index'))
    elif request.method == 'POST':
        delete = request.form['delete']
        id = request.form['id']
        if delete == 'Delete':
            #delete doc
            doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).one()

            #delete docs tags
            for tag in doc.tags:
                doc.tags.remove(tag)

            #delete docs authors
            for author in doc.authors:
                doc.authors.remove(author)

            #delete it
            doc = current_user.documents.filter(Documents.id==id, Documents.source_id==3).delete()

            db.session.commit()
            flash("Item deleted.")
            return redirect(url_for('index'))
        if delete == 'Cancel':
            flash("Item not deleted.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@native_blueprint.route('/tags/edit', methods=['GET', 'POST'])
@login_required
def bulk_edit():
    if request.method == 'GET':
        #display tags just like in /tags, but only for native docs
        #tags = db.session.query(Tags.name).filter_by(user_id=current_user.id, source_id="3").order_by(Tags.name).distinct()
        tags = db.session.query(Tags.name).join(Documents).filter(Documents.user_id==current_user.id, Documents.source_id=="3").\
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
## IMPORT BOOKMARKS FROM HTML FILE #############################################
# also source_id 3

@native_blueprint.route('/import', methods=['GET', 'POST'])
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
                                new_doc = Documents(3, each.string)
                                current_user.docsuments.append(new_doc)
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

