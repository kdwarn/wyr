import datetime
import math
import pytz
from xml.etree import ElementTree

from flask import Blueprint, request, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from requests_oauthlib import OAuth1Session
from sqlalchemy.orm.exc import NoResultFound

from app import db
from .models import Documents, SourceToken
from . import common
from . import exceptions as ex

# goodreads uses Oauth1, returns xml
# https://www.goodreads.com/api
# source_id 2

goodreads_bp = Blueprint("goodreads", __name__)


def format_author(author):
    """ Input: string of author name in "first_name last_name" format.
        Output: dictionary
    """

    author = author.split(" ", maxsplit=1)

    if author[0].strip():
        try:
            author_dict = {"last_name": author[1].strip(), "first_name": author[0].strip()}
        except IndexError:  # only one name
            author_dict = {"last_name": author[0].strip(), "first_name": ""}

    return author_dict


@goodreads_bp.route("/goodreads")
@login_required
def goodreads_login():
    goodreads_config = current_app.config["GOODREADS_CONFIG"]

    goodreads = OAuth1Session(
        goodreads_config["client_id"], client_secret=goodreads_config["client_secret"]
    )

    fetch_response = goodreads.fetch_request_token(goodreads_config["request_token_url"])

    session["resource_owner_key"] = fetch_response.get("oauth_token")
    session["resource_owner_secret"] = fetch_response.get("oauth_token_secret")

    authorization_url = goodreads.authorization_url(goodreads_config["authorize_url"])

    return redirect(authorization_url)


@goodreads_bp.route("/goodreads/authorization")
@login_required
def goodreads_authorize():

    goodreads_config = current_app.config["GOODREADS_CONFIG"]

    authorize = request.args.get("authorize")

    if authorize == "1":
        # get access token
        auth_object = OAuth1Session(
            goodreads_config["client_id"],
            client_secret=goodreads_config["client_secret"],
            resource_owner_key=session["resource_owner_key"],
            resource_owner_secret=session["resource_owner_secret"],
        )

        # Goodreads doesn't (but is supposed to) send back a "verifier" value
        # the verifier='unused' hack I found at
        # https://github.com/requests/requests-oauthlib/issues/115
        tokens = auth_object.fetch_access_token(
            goodreads_config["access_token_url"], verifier="unused"
        )

        # access token and access token secret
        access_token = tokens.get("oauth_token")
        access_token_secret = tokens.get("oauth_token_secret")

        # update User db record - flag them as Goodreads user
        current_user.goodreads = 1

        # save token in Tokens table
        tokens = SourceToken(
            user_id=current_user.id,
            source_id=2,
            access_token=access_token,
            access_token_secret=access_token_secret,
        )

        db.session.add(tokens)
        db.session.commit()

        flash("Authorization successful.")
        return redirect(url_for("main.verify_authorization", source="Goodreads"))

    else:
        flash("Authorization failed.")
        return redirect(url_for("main.settings"))


def import_goodreads(update_type):
    """Connect to Goodreads and initiate process of collecting info."""

    goodreads_config = current_app.config["GOODREADS_CONFIG"]

    # get tokens from Tokens table
    tokens = SourceToken.query.filter_by(user_id=current_user.id, source_id=2).first()

    # get Oauth object
    auth_object = OAuth1Session(
        goodreads_config["client_id"],
        client_secret=goodreads_config["client_secret"],
        resource_owner_key=tokens.access_token,
        resource_owner_secret=tokens.access_token_secret,
    )

    get_books_from_shelf(auth_object, "read", update_type)

    # get books in the 'to-read' shelf if user wants them
    if current_user.include_g_unread == 1:
        get_books_from_shelf(auth_object, "to-read", update_type)

    return


def get_books_from_shelf(auth_object, shelf, update_type):
    """ Get Books from shelf, determine what to do with them."""

    goodreads_config = current_app.config["GOODREADS_CONFIG"]

    # first need to figure out how many pages, b/c limited to 200 items per call
    payload = {
        "v": "2",
        "key": goodreads_config["client_id"],
        "shelf": shelf,
        "sort": "date_updated",
    }

    r = auth_object.get("https://www.goodreads.com/review/list.xml", params=payload)

    # if no books found, return
    if r.status_code != 200:
        flash("You don't appear to have books on your Goodreads {} shelf.".format(shelf))
    else:
        root = ElementTree.fromstring(r.content)

        # figure out how many pages of results
        total = root[2].get("total")
        pages = math.ceil(int(total) / 200)

        book_ids = []  # list to determine if any books were deleted

        # go through each page (1-based numbering)
        for i in range(1, pages + 1):

            payload = {
                "v": "2",
                "key": goodreads_config["client_id"],
                "shelf": shelf,
                "per_page": "200",
                "page": "{}".format(i),
            }
            r = auth_object.get("https://www.goodreads.com/review/list.xml", params=payload)

            root = ElementTree.fromstring(r.content)

            # go through each book, and see if we need to insert/update it
            for review in root[2]:  # root[2] is *reviews* top-level xml

                if update_type == "initial":
                    book = get_book_details(review, shelf)
                    try:
                        common.add_item(book, current_user, source="goodreads")
                    except ex.NoTitleException:
                        continue  # all books should have a title, so just skip book if somehow there isn't one
                elif update_type == "normal":
                    # do this at this at the top so it is added even if we don't get to get_book_details()
                    # Used for removing deleted books from db.
                    book_ids.append(review.find("id").text)

                    date_updated = datetime.datetime.strptime(
                        review.find("date_updated").text, "%a %b %d %H:%M:%S %z %Y"
                    )

                    # convert from localtime to UTC
                    date_updated = date_updated.astimezone(pytz.utc).replace(tzinfo=None)

                    if date_updated < current_user.goodreads_update:
                        continue

                    book = get_book_details(review, shelf)

                    # edit or add it
                    try:
                        doc = current_user.documents.filter(
                            Documents.source_id == 2,
                            Documents.native_doc_id == book["native_doc_id"],
                        ).one()
                        book["id"] = doc.id
                        try:
                            common.edit_item(book, current_user, source="goodreads")
                        except ex.NoTitleException:
                            continue  # all books should have a title, so just skip book if somehow there isn't one
                    except NoResultFound:
                        try:
                            common.add_item(book, current_user, source="goodreads")
                        except ex.NoTitleException:
                            continue  # all books should have a title, so just skip book if somehow there isn't one
                elif update_type == "unread_update":
                    book = get_book_details(review, shelf)

                    # add to list to check for deleted books
                    book_ids.append(book["native_doc_id"])

                    # edit or add it
                    try:
                        doc = current_user.documents.filter(
                            Documents.source_id == 2,
                            Documents.native_doc_id == book["native_doc_id"],
                        ).one()
                        book["id"] = doc.id
                        try:
                            common.edit_item(book, current_user, source="goodreads")
                        except ex.NoTitleException:
                            continue  # all books should have a title, so just skip book if somehow there isn't one
                    except NoResultFound:
                        try:
                            common.add_item(book, current_user, source="goodreads")
                        except ex.NoTitleException:
                            continue  # all books should have a title, so just skip book if somehow there isn't one

        if update_type in ["normal", "unread_update"]:
            delete_books(book_ids, shelf)

        flash(f"Books on your Goodreads {shelf} shelf have been updated.")

    # current_user.goodreads_update = datetime.datetime.now(pytz.utc)
    current_user.goodreads_update = datetime.datetime.utcnow()
    db.session.commit()

    return


def get_book_details(review, shelf):
    """
    Get book info from Goodreads and structure it for sending to common.add_item or common.edit_item.

    review -- review xml block from goodreads
    shelf -- the Goodreads shelf ('to-read' or 'read')
    """

    content = {}
    content["title"] = review.find("book/title").text
    content["link"] = review.find("book/link").text
    content["native_doc_id"] = review.find("id").text
    content["read"] = 1 if shelf == "read" else 0

    if review.find("book/published").text is not None:
        content["year"] = review.find("book/published").text

    if review.find("read_at").text is not None:
        created = datetime.datetime.strptime(review.find("read_at").text, "%a %b %d %H:%M:%S %z %Y")
    else:
        created = datetime.datetime.strptime(
            review.find("date_added").text, "%a %b %d %H:%M:%S %z %Y"
        )
    # convert from localtime to to UTC
    content["created"] = created.astimezone(pytz.utc)

    if review.find("body").text is not None:
        content["notes"] = review.find("body").text

    if review.find("shelves/shelf") is not None:
        # make list of tags out of shelves this book is on
        tags = []
        for book_shelf in review.findall("shelves/shelf"):
            # don't add the 'read' or 'to-read' shelves as a tag
            if book_shelf.get("name") == "read" or book_shelf.get("name") == "to-read":
                continue
            tags.append(book_shelf.get("name"))
        content["tags"] = tags

    if review.find("book/authors/author/name") is not None:
        authors = []
        for name in review.findall("book/authors/author/name"):
            author = format_author(name.text)
            authors.append(author)
        content["authors"] = authors

    return content


def delete_books(book_ids, shelf):
    """Remove deleted books from db."""

    read = 0 if shelf == "to-read" else 1

    books = Documents.query.filter_by(user_id=current_user.id, source_id=2, read=read).all()

    for book in books:
        if book.native_doc_id not in book_ids:
            try:
                common.delete_item(book.id, current_user)
            except ex.NotUserDocException:
                pass

    return
