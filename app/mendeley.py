import datetime
import pytz

from flask import Blueprint, request, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from requests_oauthlib import OAuth2Session
from werkzeug.routing import RequestRedirect

from app import db
from .models import Documents, SourceToken, FileLinks
from . import common


# Mendeley uses Oauth 2, returns json
# source_id = 1

mendeley_bp = Blueprint("mendeley", __name__, template_folder="templates")


@mendeley_bp.route("/mendeley")
@login_required
def mendeley_login():
    m = current_app.config["MENDELEY_CONFIG"]

    mendeley = OAuth2Session(
        client_id=m["client_id"], redirect_uri=m["redirect_uri"], scope=m["scope"]
    )

    authorization_url, state = mendeley.authorization_url(m["authorize_url"])

    # *state* is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    return redirect(authorization_url)


@mendeley_bp.route("/mendeley/authorization")
@login_required
def mendeley_authorize():
    m = current_app.config["MENDELEY_CONFIG"]

    if request.args.get("error"):
        flash("Sorry, there has been an error (" + request.args.get("error_description") + ").")
        return redirect(url_for("main.settings"))

    # get vars from redirect
    code = request.args.get("code")
    state = request.args.get("state")

    # check against CSRF attacks
    if state != session["oauth_state"]:
        flash("Sorry, there has been an error.")
        return redirect(url_for("main.settings"))

    mendeley = OAuth2Session(
        m["client_id"], state=session["oauth_state"], redirect_uri=m["redirect_uri"]
    )

    # fetch token from Mendeley
    token = mendeley.fetch_token(
        m["token_url"], code=code, username=m["client_id"], password=m["client_secret"]
    )

    if request.args.get("error"):
        flash("Sorry, there has been an error (" + request.args.get("error_description") + ").")
        return redirect(url_for("main.settings"))

    # save token in db
    db_token = SourceToken(
        user_id=current_user.id,
        source_id=1,
        access_token=token["access_token"],
        refresh_token=token["refresh_token"],
    )

    db.session.add(db_token)
    current_user.mendeley = 1
    db.session.commit()

    flash("Authorization successful.")
    return redirect(url_for("main.verify_authorization", source="Mendeley"))


def update_token(new_token):
    token = SourceToken.query.filter_by(user_id=current_user.id, source_id=1).first()
    token.access_token = new_token["access_token"]
    token.refresh_token = new_token["refresh_token"]
    db.session.commit()


def refresh_token():
    m = current_app.config["MENDELEY_CONFIG"]
    """
    refreshes access token, and possibly refresh token, stores in db

    returns 0auth object, which can then be used to query docs
    """

    # get existing tokens from Source Tokens table
    tokens = SourceToken.query.filter_by(user_id=current_user.id, source_id=1).first()

    # put token info into dict
    token = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_in": -30,
    }

    extra = {"client_id": m["client_id"], "client_secret": m["client_secret"]}

    # refresh token, get 0auth object
    auth_object = OAuth2Session(
        m["client_id"],
        token=token,
        auto_refresh_url=m["refresh_url"],
        auto_refresh_kwargs=extra,
        token_updater=update_token,
    )

    return auth_object


def import_mendeley(update_type):
    """
    Import items from Mendeley, determine what to do with them.

    update_type -- 'initial', 'normal', or 'unread'
    initial = first time importing
    normal = normal importing on regular basis
    unread = special case where user has just switched pref to include
             or exclude unread items
    """

    # refresh token and get 0auth object
    mendeley = refresh_token()

    # remove any items from db that were deleted in Mendeley
    if update_type != "initial":
        docs_to_delete = get_docs(mendeley, "delete")

        if docs_to_delete:
            for doc in docs_to_delete:
                Documents.query.filter_by(
                    user_id=current_user.id, source_id=1, native_doc_id=doc["id"]
                ).delete()
            db.session.commit()
            if len(docs_to_delete) == 1:
                flash("1 item had been deleted in Mendeley and was removed.")
            else:
                flash(
                    "{} items had been deleted in Mendeley and were removed.".format(
                        len(docs_to_delete)
                    )
                )

    # now get current docs
    docs = get_docs(mendeley, update_type)

    # set a count var to let user know how many items updated if "unread_update"
    if update_type == "unread_update":
        count = 0

    if docs:
        # go through each doc, and see if we need to insert or update it
        for doc in docs:

            # skip unread items if user doesn't want them
            if current_user.include_m_unread == 0 and doc["read"] == 0:
                continue

            # skip read items if this is an "unread_update"
            if update_type == "unread_update" and doc["read"] == 1:
                continue
            if update_type == "unread_update" and doc["read"] == 0:
                count += 1

            if update_type != "initial":
                # see if the doc is already in the db
                check_doc = Documents.query.filter_by(
                    user_id=current_user.id, source_id=1, native_doc_id=doc["id"]
                ).first()
                save_doc(doc, mendeley, check_doc)
            else:
                save_doc(doc, mendeley)

        if update_type == "unread_update":
            if count > 1:
                flash("{} unread items from Mendeley added.".format(count))
            else:
                flash("1 unread item from Mendeley added.")
        else:
            if len(docs) == 1:
                flash("1 item updated from Mendeley.")
            else:
                flash("{} items updated from Mendeley.".format(len(docs)))
    else:
        flash("No updated items were found in Mendeley.")

    current_user.mendeley_update = datetime.datetime.now(pytz.utc)
    db.session.commit()


def get_docs(auth_object, type=""):
    """Get docs from Mendeley."""

    # set parameters
    if type == "initial" or type == "unread_update":
        payload = {"limit": "500", "order": "desc", "sort": "created", "view": "all"}

    if type == "normal":
        # if this is an update, only get docs modified since last update
        # covert last time mendeley was updated to iso format (8601)
        modified_since = current_user.mendeley_update.isoformat()
        payload = {"limit": "500", "view": "all", "modified_since": modified_since}

    if type == "delete":
        # get docs to delete
        modified_since = current_user.mendeley_update.isoformat()
        payload = {"limit": "500", "deleted_since": modified_since, "include_trashed": "true"}

    try:
        r = auth_object.get("https://api.mendeley.com/documents", params=payload)
    except InvalidGrantError:
        # Something has gone wrong with authorization. Use RequestRedirect
        # to directly return from this function.
        common.force_remove("Mendeley")
        flash("There was an error with your Mendeley account. Please re-authorize it.")
        raise RequestRedirect(url_for("main.settings"))

    docs = r.json()

    # if no docs found, return empty docs variable
    if r.status_code != 200:
        docs = ""

    # get the docs
    else:
        # If multiple pages of docs, Mendeley provides a "next" link - this code
        # pulls that out of .headers['link'], strips out non-link characters,
        # and calls it
        if "link" in r.headers:
            while 'rel="next"' in r.headers["link"]:
                mendeley_link = r.headers["link"].split(">")
                mendeley_link = mendeley_link[0].strip("<")
                r = auth_object.get(mendeley_link)

                # add new list of docs to old one
                docs = docs + r.json()

    return docs


def save_doc(m_doc, auth_object, existing_doc=""):
    """
    Save doc (insert or update in db).

    m_doc -- the doc object from mendeley
    auth_object -- auth object from Mendeley
    existing_doc -- doc object from WYR Document object
    """

    if not existing_doc:  # inserting, create Document object
        doc = Documents(current_user, 1, m_doc["title"])
        current_user.documents.append(doc)
    else:  # updating, Document object already exists
        doc = existing_doc
        doc.title = m_doc["title"]

    doc.created = m_doc["created"]  # already in UTC
    doc.read = m_doc["read"]
    doc.starred = m_doc["starred"]
    doc.native_doc_id = m_doc["id"]
    doc.read = int(m_doc["read"])
    doc.year = m_doc.get("year")
    doc.last_modified = m_doc.get("last_modified")  # already in UTC
    if "websites" in m_doc:
        doc.link = m_doc["websites"][0]  # only include first link

    # get notes
    an_params = {"document_id": m_doc["id"], "type": "note"}
    annotations = auth_object.get("https://api.mendeley.com/annotations", params=an_params).json()
    try:
        doc.notes = annotations[0]["text"]
    except KeyError:
        pass
    except IndexError:
        pass

    # get file id to link to
    file_params = {"document_id": m_doc["id"]}
    files = auth_object.get("https://api.mendeley.com/files", params=file_params).json()

    db.session.add(doc)
    db.session.commit()

    print(doc.title)

    # insert
    if not existing_doc:
        if "tags" in m_doc:  # to-read tag set later, if necessary
            common.add_or_update_tags(current_user, m_doc["tags"], doc)
        if "authors" in m_doc:
            # no need to format, already in list of dict with keys last_name and first_name
            common.add_or_update_authors(current_user, m_doc["authors"], doc)
        if "editors" in m_doc:
            # same as authors
            common.add_or_update_authors(current_user, m_doc["editors"], doc)
        if files:
            for file in files:
                new_filelink = FileLinks(doc.id, file["id"])
                new_filelink.mime_type = file["mime_type"]
                db.session.add(new_filelink)

    # update
    else:
        # set tags variable so it can be used below, even if empty
        try:
            tags = m_doc["tags"]
        except KeyError:
            tags = ""

        # update tags
        if tags:
            common.add_or_update_tags(current_user, tags, doc)

        # authors
        try:
            authors = m_doc["authors"]
        except KeyError:
            authors = []

        # editors
        try:
            editors = m_doc["editors"]
        except KeyError:
            editors = []

        # combine list of authors & editors, b/c we aren't differentiating
        authors = authors + editors

        if authors:  # authors and editors
            # no need to format, already in list of dict with keys last_name and first_name
            common.add_or_update_authors(current_user, authors, doc)

        # files
        old_file_links = doc.file_links

        # one scenario not caught by "if files:" below: there were old files, but no
        # new files (user deleted one/all). Have to treat this separately.
        if old_file_links and not files:
            for old_file_link in old_file_links:
                doc.file_links.remove(old_file_link)

        if files:
            # create list of file_ids to check against
            file_ids = [file["id"] for file in files]

            # check old file list against files submitted after edit, remove any no longer there
            if old_file_links:
                for old_file_link in old_file_links:
                    if old_file_link.file_link not in file_ids:
                        doc.file_links.remove(old_file_link)

                # don't add files if they were already in old_files - would be a duplicate
                for file in files[:]:
                    if file["id"] in file_ids:
                        files.remove(file)

            # add new files
            for file in files:
                new_filelink = FileLinks(doc.id, file["id"])
                new_filelink.mime_type = file["mime_type"]
                db.session.add(new_filelink)

    db.session.commit()
