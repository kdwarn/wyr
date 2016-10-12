from flask import Blueprint, render_template, request, redirect, url_for, flash
from jinja2 import TemplateNotFound
from flask.ext.login import login_required, current_user
from datetime import datetime
from wyr.sources.source_functions import get_user_tags, get_user_tag_names, get_user_authors, \
    get_user_author_names, str_tags_to_list, str_authors_to_list

from app import db

from models import Documents, Tags, Authors

native = Blueprint('test', __name__, template_folder='templates')

@native.route('/edit2', methods=['GET', 'POST'])
@login_required
def edit2():

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
