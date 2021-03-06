from collections import namedtuple
import datetime

from bs4 import BeautifulSoup
from flask import Blueprint, render_template, request, redirect, session, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy.orm.exc import NoResultFound
from app import db
from .models import Documents
from . import common
from . import exceptions as ex


native_bp = Blueprint("native", __name__)

############
# WYR NATIVE
# source_id = 3


def str_tags_to_list(tags):
    """Convert string of comma separated tags to list, stripped of empty tags and whitespace."""

    tags = tags.split(",")

    tags = [tag.strip() for tag in tags if tag.strip()]

    return tags


def format_authors(authors):
    """ Input: string of (possibly comma- and semi-colon-separated) authors
        Output: list of dicts, stripped of empty authors and whitesapce
    """

    list_of_authors = []

    for author in authors[:].split(";"):
        if any(char.isalnum() for char in author):
            author = author.split(",", maxsplit=1)

            try:
                a = {"last_name": author[0].strip(), "first_name": author[1].strip()}
            except IndexError:
                a = {"last_name": author[0].strip(), "first_name": ""}

            list_of_authors.append(a)

    return list_of_authors


@native_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":

        # although only 2 vars may be populated, create full object bc this
        # goes to same template as editing doc and will reduce if/else in temp
        title = request.args.get("title", "")
        link = request.args.get("link", "")
        from_bookmarklet = request.args.get("bookmarklet", "")

        # because add() and edit() go to same template, create namedtuple for ease of use
        doc = namedtuple("doc", ["title", "link", "year", "notes"])
        doc.title = title
        doc.link = link
        doc.year, doc.notes, tags, authors = "", "", "", ""

        # also pass along tags and author names for autocomplete
        all_tags = common.get_user_tags(current_user)
        all_tags = [tag.name for tag in all_tags]
        all_authors = common.get_user_authors(current_user)
        all_authors = [author.last_name + ", " + author.first_name for author in all_authors]

        # check if link already exists, redirect user to edit if so
        if link:
            if (
                current_user.documents.filter(
                    Documents.link == link, Documents.source_id == 3
                ).count()
                >= 1
            ):
                doc = current_user.documents.filter(
                    Documents.link == link, Documents.source_id == 3
                ).first()
                read_type = "read" if doc.read == 1 else "to-read"

                flash(f"You've already saved that link as {read_type}; " "you may edit it below.")
                return redirect(url_for("native.edit", id=doc.id))

        return render_template(
            "add.html",
            doc=doc,
            tags=tags,
            authors=authors,
            all_tags=all_tags,
            all_authors=all_authors,
            from_bookmarklet=from_bookmarklet,
        )

    elif request.method == "POST":

        content = {}
        content["title"] = request.form.get("title")
        content["link"] = request.form.get("link")
        content["tags"] = request.form.get("tags")
        content["authors"] = request.form.get("authors")
        content["year"] = request.form.get("year")
        content["notes"] = request.form.get("notes")
        content["read"] = request.form.get("read")

        if content["tags"]:
            content["tags"] = str_tags_to_list(content["tags"])

        if content["authors"]:
            content["authors"] = format_authors(content["authors"])

        try:
            common.add_item(content, current_user, source="native")
        except ex.NoTitleException as e:
            flash(e.message)
            return redirect(url_for("native.add"))
        except ex.DuplicateLinkException as e:
            flash(e.message)
            return redirect(url_for("native.edit", id=e.doc_id))

        flash("Item added.")

        if content.get("from_bookmarklet"):
            return render_template("add.html", bookmarklet=1)

        if content.get("another"):
            return redirect(url_for("native.add"))

        return redirect(url_for("main.index"))


@native_bp.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "GET":
        id = request.args.get("id", "")

        try:
            doc = current_user.documents.filter(Documents.id == id, Documents.source_id == 3).one()
        except NoResultFound:
            flash("That document was not found in your collection.")
            return redirect(url_for("main.index"))
        else:
            new_tags = ""
            new_authors_list = []
            new_authors = ""

            # have to format tags and authors for form
            if doc.tags:
                super_new_tag_list = [tag.name for tag in doc.tags]
                super_new_tag_list.sort()
                for name in super_new_tag_list:
                    if name != super_new_tag_list[-1]:
                        new_tags += name + ", "
                    else:
                        new_tags += name

            if doc.authors:
                for author in doc.authors:
                    new_authors_list.append(author)

            for author in new_authors_list:
                if author != new_authors_list[-1]:
                    new_authors += author.last_name + ", " + author.first_name + "; "
                else:
                    new_authors += author.last_name + ", " + author.first_name

            # also pass along all tags and authors for autocomplete
            all_tags = common.get_user_tags(current_user)
            all_tags = [tag.name for tag in all_tags]
            all_authors = common.get_user_authors(current_user)
            all_authors = [author.last_name + ", " + author.first_name for author in all_authors]

            return render_template(
                "add.html",
                edit=1,
                doc=doc,
                tags=new_tags,
                all_tags=all_tags,
                all_authors=all_authors,
                authors=new_authors,
            )

    elif request.method == "POST":

        content = {}
        content["id"] = request.form.get("id")
        content["title"] = request.form.get("title")
        content["link"] = request.form.get("link")
        content["tags"] = request.form.get("tags")
        content["authors"] = request.form.get("authors")
        content["year"] = request.form.get("year")
        content["notes"] = request.form.get("notes")
        content["read"] = request.form.get("read")

        if content["tags"]:
            content["tags"] = str_tags_to_list(content["tags"])

        if content["authors"]:
            content["authors"] = format_authors(content["authors"])

        try:
            common.edit_item(content, current_user, source="native")
        except ex.NotUserDocException as e:
            flash(e.message)
            return redirect(url_for("main.index"))
        except ex.NoTitleException as e:
            flash(e.message)
            return redirect(url_for("native.edit", id=e.doc_id))
        except ex.DuplicateLinkException as e:
            flash(e.message)
            return redirect(url_for("native.edit", id=e.doc_id))
        else:
            flash("Item edited.")
            return redirect(request.form.get("referrer"))


@native_bp.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    """Delete one of the user's documents."""

    if request.method == "GET":
        # check that doc is one of current_user's
        id = request.args.get("id", "")

        try:
            doc = current_user.documents.filter(Documents.id == id, Documents.source_id == 3).one()
        except NoResultFound:
            flash("That document was not found in your collection.")
            return redirect(url_for("main.index"))

        read_status = "to-read" if doc.read == 0 else "read"

        return render_template("delete.html", doc=doc, read_status=read_status)

    elif request.method == "POST":
        delete = request.form["delete"]
        id = request.form["id"]

        if delete == "Cancel":
            flash("Item not deleted.")
            return redirect(request.form.get("referrer"))

        if delete == "Delete":
            try:
                common.delete_item(id, current_user)
            except ex.NotUserDocException as e:
                flash(e.message)
                return redirect(url_for("main.index"))

            flash("Item deleted.")
            return redirect(request.form.get("referrer"))


@native_bp.route("/import", methods=["GET", "POST"])
@login_required
def import_bookmarks():
    """Import bookmarks from HTML file."""
    if request.method == "GET":
        return render_template("import.html")

    if "step1" in request.form:

        if request.form["step1"] == "Cancel":
            flash("Bookmarks import cancelled.")
            return redirect(url_for("main.settings"))

        file = request.files["bookmarks"]

        if not file:
            flash("No file was selected. Please choose a file.")
            return render_template("import.html")

        file_extension = file.filename.rsplit(".", 1)[1]
        if file_extension != "html":
            flash("Sorry, that doesn't look like a .html file.")
            return render_template("import.html")

        soup = BeautifulSoup(file, "html.parser")

        folders = []
        for each in soup.find_all("h3"):
            folders.append(each.string)

        bookmarks = []
        for each in soup.find_all("a"):
            if each.string:
                # get the dl (list within the folder) above the link
                parent_dl = each.find_parent("dl")
                # get the dt (folder) above that
                grandparent_dt = parent_dl.find_parent("dt")
                if grandparent_dt:
                    # get the h3 (folder name) below the grandparent dt
                    h3 = grandparent_dt.find_next("h3")
                    if h3:
                        bookmark = {
                            "folder": h3.string,
                            "title": each.string,
                            "link": each["href"],
                            "tags": [h3.string.replace(",", " ")],
                            "created": each["add_date"],
                        }
                        bookmarks.append(bookmark)

        session["bookmarks"] = bookmarks
        return render_template("import.html", step2="yes", folders=folders)

    if "step2" in request.form:

        if request.form["step2"] == "Cancel":
            flash("Bookmarks import cancelled.")
            return redirect(url_for("main.settings"))

        folders = request.form.getlist("folder")

        for bookmark in session["bookmarks"]:
            if bookmark["folder"] in folders:
                new_doc = Documents(
                    current_user.id,
                    3,
                    bookmark["title"],
                    link=bookmark["link"],
                    created=datetime.datetime.fromtimestamp(int(bookmark["created"])),
                    read=1,
                )
                current_user.documents.append(new_doc)
                db.session.commit()
                common.add_or_update_tags(current_user, bookmark["tags"], new_doc)
                db.session.commit()

        session.pop("bookmarks")
        flash("Bookmarks successfully imported.")
        return redirect(url_for("main.index"))
