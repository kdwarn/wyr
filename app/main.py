# TODO: create function to revoke authorized clients

from collections import OrderedDict
import datetime
import secrets
import string

from flask import Blueprint, render_template, request, redirect, url_for, abort, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, URLSafeSerializer
from passlib.context import CryptContext
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound
import stripe

from app import db
from .models import User, Documents, Tags, Bunches, Authors, Client
from . import exceptions as ex
from . import mendeley
from . import goodreads
from . import common


bp = Blueprint("main", __name__)


#######################
# MAIN DISPLAY ROUTES #
#######################


@bp.route("/")
def index():
    """ Return documents or settings page for authenticated page, else return
    main sign up/info page.

    This also is where the function to update non-native docs is called.
    """

    if current_user.is_authenticated:

        one_week_ago = datetime.datetime.now() - datetime.timedelta(days=7)

        # update items from any sources if last update was > one week ago.
        # it's possible the user didn't immediately import source items after
        # authorizing, check for that
        if current_user.mendeley == 1 and not current_user.mendeley_update:
            mendeley.import_mendeley("initial")
        if current_user.mendeley == 1 and current_user.mendeley_update < one_week_ago:
            mendeley.import_mendeley("normal")

        if current_user.goodreads == 1 and not current_user.goodreads_update:
            goodreads.import_goodreads("initial")
        if current_user.goodreads == 1 and current_user.goodreads_update < one_week_ago:
            goodreads.import_goodreads("normal")

        docs = common.get_docs(current_user)

        return render_template("read.html", docs=docs, read_status="all")

    return render_template("index.html")


@bp.route("/<id>/")
@login_required
def permalink(id):
    """Return one document."""
    try:
        doc = current_user.documents.filter(Documents.id == id).one()
    except NoResultFound:
        flash("That document was not found in your collection.")
        return redirect(url_for("main.index"))
    else:
        return render_template("permalink.html", doc=doc)


@bp.route("/read")
@login_required
def read():
    """Return all read items."""
    docs = common.get_docs(current_user, read_status="read")

    return render_template("read.html", docs=docs, read_status="read")


@bp.route("/to-read")
@login_required
def to_read():
    """ Return all unread items."""
    docs = common.get_docs(current_user, read_status="to-read")

    return render_template("read.html", docs=docs, read_status="to-read")


@bp.route("/tags")
@login_required
def tags():
    """ Return page of all tags, which user can select to display documents with that tag. """
    tags = common.get_user_tags(current_user)

    if not tags:
        grouped_tags = ""
    else:
        # group tags by their first letter, to enable jumping down page
        grouped_tags = OrderedDict()

        for tag in tags:
            if tag.name[0] not in string.ascii_letters:
                try:
                    grouped_tags["#"].append(tag)
                except KeyError:
                    grouped_tags["#"] = []
                    grouped_tags["#"].append(tag)
            else:
                try:
                    grouped_tags[tag.name[0].upper()].append(tag)
                except KeyError:
                    grouped_tags[tag.name[0].upper()] = []
                    grouped_tags[tag.name[0].upper()].append(tag)

    return render_template("tags.html", grouped_tags=grouped_tags)


@bp.route("/<read_status>/tag/<tag>/")
@login_required
def docs_by_tag(read_status, tag):
    """Return all user's documents tagged <tag>."""
    docs = common.get_docs(current_user, read_status=read_status, tag=tag)

    # tagpage is used for header
    return render_template("read.html", docs=docs, tagpage=tag, read_status=read_status)


@bp.route("/<read_status>/bunch/<name>")
@login_required
def bunch(read_status, name):
    """
    Display docs from saved bunch
    defaults={'read_status':'all'}
    """

    try:
        docs = common.get_docs(current_user, read_status=read_status, bunch=name)
    except ex.NoBunchException:
        flash(f"No bunch named {name} found.")
        return redirect(url_for("main.index"))

    user_bunch = Bunches.query.filter(
        Bunches.user_id == current_user.id, Bunches.name == name
    ).one()

    return render_template(
        "read.html",
        docs=docs,
        bunch_tag_names=[tag.name for tag in user_bunch.tags],
        bunch_name=name,
        read_status=read_status,
        selector=user_bunch.selector,
    )


@bp.route("/bunches", methods=["GET", "POST"])
@login_required
def bunches():
    """
    Let user select multiple tags and display the docs that fit the criteria.
    Include link to save the bunch, which takes place through bunch_save().
    """

    if request.method == "POST":
        selector = request.form["selector"]  # "and" or "or"
        bunch_tags = request.form.getlist("bunch_tags")  # these are ids of chosen tags

        if not bunch_tags:
            flash("You did not choose any tags.")
            return redirect(url_for("main.bunches"))

        filters = []

        if selector == "or":
            filters.append(Documents.tags.any(Tags.id.in_([t for t in bunch_tags])))
        elif selector == "and":
            for tag in bunch_tags:
                filters.append(Documents.tags.any(id=tag))

        docs = current_user.documents.filter(*filters).order_by(desc(Documents.created)).all()

        if not docs:
            flash("Sorry, no items matched your tag choices.")
            return redirect(url_for("main.bunches"))

        # get tag names and put in list
        bunch_tag_names = []

        for tag in bunch_tags:
            tag = Tags.query.filter(Tags.id == tag).one()
            bunch_tag_names.append(tag.name)

        # convert bunch_tags into string for hidden input in form
        bunch_tag_ids = ",".join(bunch_tags)

        # return docs as well as list of tags and how they were chosen
        return render_template(
            "read.html",
            docs=docs,
            bunch_tag_names=bunch_tag_names,
            bunch_tag_ids=bunch_tag_ids,
            selector=selector,
        )

    tags = common.get_user_tags(current_user)

    if not tags:
        tags = ""
        bunches = ""
    else:
        bunches = Bunches.query.filter(Bunches.user_id == current_user.id).all()

    return render_template("bunches.html", tags=tags, bunches=bunches)


@bp.route("/bunch/save", methods=["GET", "POST"])
@login_required
def bunch_save():
    """ Process a bunch save request from a user."""

    selector = request.form["selector"]
    bunch_name = request.form["bunch_name"]
    bunch_tag_ids = request.form["bunch_tag_ids"]

    new_bunch = Bunches(current_user.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    # get each tag object and append to new_bunch.tags
    for tag in bunch_tag_ids.split(","):
        existing_tag = Tags.query.filter(Tags.id == tag).one()
        new_bunch.tags.append(existing_tag)

    db.session.commit()

    flash(f"New bunch {bunch_name} saved.")
    return redirect(url_for("main.bunches"))


@bp.route("/bunch/edit", methods=["GET", "POST"])
@login_required
def bunch_edit():
    """Edit a bunch."""

    if request.method == "POST":
        if request.form["submit"] == "cancel":
            flash("Edit canceled.")
            return redirect(url_for("main.bunches"))

        old_bunch_name = request.form["old_bunch_name"]
        new_bunch_name = request.form["new_bunch_name"]
        selector = request.form["selector"]
        bunch_tags = request.form.getlist("bunch_tags")  # ids

        if not bunch_tags:
            flash("You didn't choose any tags.")
            return redirect(url_for("main.bunches"))

        try:
            bunch = Bunches.query.filter(
                Bunches.user_id == current_user.id, Bunches.name == old_bunch_name
            ).one()
        except NoResultFound:
            flash("Sorry, there was an error fetching the bunch.")
            return redirect(url_for("main.bunches"))

        # check that name isn't duplicate
        if old_bunch_name != new_bunch_name:
            if (
                Bunches.query.filter(
                    Bunches.user_id == current_user.id, Bunches.name == new_bunch_name
                ).first()
                is not None
            ):
                flash(f"You already have a bunch named {new_bunch_name}.")
                return redirect(url_for("main.bunch_edit", name=bunch.name))

        bunch.selector = selector
        bunch.name = new_bunch_name

        # get tag ids of tags currently in bunch
        old_bunch_tags = [tag.id for tag in bunch.tags]

        # add new tags
        for tag in bunch_tags[:]:
            if tag not in old_bunch_tags:
                tag = Tags.query.filter(Tags.id == tag).one()
                bunch.tags.append(tag)

        # remove old tags
        for old_tag in old_bunch_tags[:]:
            if old_tag not in bunch_tags:
                old_tag = Tags.query.filter(Tags.id == old_tag).one()
                bunch.tags.remove(old_tag)

        db.session.commit()

        flash("Bunch edited.")
        return redirect(url_for("main.bunches"))  # TODO: or maybe this should go to bunch/<name>?

    bunch_name = request.args.get("name", "")
    bunch = Bunches.query.filter(
        Bunches.user_id == current_user.id, Bunches.name == bunch_name
    ).one()
    tags = common.get_user_tags(current_user)
    return render_template("bunch_edit.html", bunch=bunch, tags=tags)


@bp.route("/bunch/delete", methods=["GET", "POST"])
@login_required
def bunch_delete():
    """Delete a bunch."""

    if request.method == "POST":
        if request.form["submit"] == "cancel":
            flash("Deletion canceled.")
            return redirect(url_for("main.bunches"))

        bunch_name = request.form["bunch_name"]

        # TODO: should do a try/except here
        bunch = Bunches.query.filter(
            Bunches.user_id == current_user.id, Bunches.name == bunch_name
        ).one()
        db.session.delete(bunch)
        db.session.commit()

        flash("Bunch deleted.")
        return redirect(url_for("main.bunches"))

    name = request.args.get("name", "")
    bunch_name = request.args.get("bunch_name")
    return render_template("bunch_delete.html", bunch_name=name)


@bp.route("/authors")
@login_required
def authors():
    """Display all authors for user's documents."""
    authors = common.get_user_authors(current_user)

    if not authors:
        grouped_authors = ""
    else:
        # group authors by first letter of last name, to enable jumping down page
        grouped_authors = OrderedDict()

        for author in authors:
            if author.last_name[0] not in string.ascii_letters:
                try:
                    grouped_authors["#"].append(author)
                except KeyError:
                    grouped_authors["#"] = []
                    grouped_authors["#"].append(author)
            else:
                try:
                    grouped_authors[author.last_name[0].upper()].append(author)
                except KeyError:
                    grouped_authors[author.last_name[0].upper()] = []
                    grouped_authors[author.last_name[0].upper()].append(author)

    return render_template("authors.html", grouped_authors=grouped_authors)


@bp.route("/<read_status>/author/<author_id>")
@login_required
def docs_by_author(read_status, author_id):
    """Return all documents by particular author."""

    docs = common.get_docs(current_user, read_status=read_status, author_id=author_id)

    try:
        author = Authors.query.filter_by(id=author_id).one()
    except NoResultFound:
        flash("Author not found.")
        return redirect(url_for("main.index"))

    # authorpage, first_name, last_name used for header
    return render_template(
        "read.html",
        docs=docs,
        authorpage=1,
        author=author,
        first_name=author.first_name,
        last_name=author.last_name,
        read_status=read_status,
    )


@bp.route("/lastmonth")
@login_required
def last_month():
    """Return all read items from last month, in chronological order."""

    one_month_ago = datetime.datetime.today() - datetime.timedelta(days=31)

    docs = (
        Documents.query.filter(
            Documents.user_id == current_user.id,
            Documents.read == 1,
            Documents.created >= one_month_ago,
        )
        .order_by(Documents.created)
        .all()
    )

    return render_template("read.html", docs=docs, read_status="read", last_month=1)


########################
# COMMON SOURCE ROUTES #
########################


@bp.route("/authorized/<source>", methods=["GET", "POST"])
@login_required
def verify_authorization(source):
    """Verification from authorizing a source, storing of initial data."""
    if request.method == "POST":
        if source == "Mendeley":
            current_user.include_m_unread = request.form["include_m_unread"]
            db.session.commit()
            mendeley.import_mendeley("initial")

        if source == "Goodreads":
            current_user.include_g_unread = request.form["include_g_unread"]
            db.session.commit()
            goodreads.import_goodreads("initial")

        return redirect(url_for("main.index"))

    return render_template("verify_and_store.html", source=source)


@bp.route("/remove", methods=["GET", "POST"])
@login_required
def remove():
    """ Remove a source and all its docs from user's WYR account. """
    if request.method == "POST":

        source = request.form["name"]
        confirm = request.form["remove"]

        if confirm == "Yes":
            common.force_remove(source)
            message = "{} has been removed.".format(source)
        else:
            message = "Deauthorization cancelled."

        flash(message)
        return redirect(url_for("main.settings"))

    return render_template("remove.html", name=request.args.get("name"))


@bp.route("/refresh")
@login_required
def refresh():
    """ Manually refresh docs from a source.
        A user could skip doing the import of items immediately after
        authorizing by going to home page, so there's a check in for that.
    """

    if request.args.get("name") == "Mendeley":
        if current_user.mendeley == 1:
            if current_user.mendeley_update:
                mendeley.import_mendeley("normal")
            else:
                mendeley.import_mendeley("initial")
            return render_template("settings.html")
    if request.args.get("name") == "Goodreads":
        if current_user.goodreads == 1:
            if current_user.goodreads_update:
                goodreads.import_goodreads("normal")
            else:
                goodreads.import_goodreads("initial")
            return render_template("settings.html")


#########################
# ADMIN/SETTINGS ROUTES #
#########################


@bp.route("/u/<username>")
@login_required
def show_user_profile(username):
    """ show the user profile for the current user."""

    if username != current_user.username:
        flash("Sorry, you cannot view that page.")
        return redirect(url_for("main.index"))
    return "Hello {}".format(username)


@bp.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    """Display form for new user to fill out; validate it and create new user account."""

    if request.method == "POST":
        username = request.form["wyr_username"]
        email = request.form["email"]

        error = 0
        if User.query.filter_by(username=username).count() > 0:
            error = 1
            flash("Sorry, username {} is already taken.".format(username))
        if User.query.filter_by(email=email).count() > 0:
            error = 1
            flash("Sorry, the email address {} is already in use.".format(email))
        if "@" not in email:
            error = 1
            flash("The email you entered does not appear to be valid.")
        if error == 1:
            return redirect(url_for("main.sign_up"))

        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        email_hash = serializer.dumps([username, email], salt="sign_up")
        subject = "Activate your account"
        text = """Please activate your account by following
        <a href="http://www.whatyouveread.com/activate?code={}">this link</a>.<br>
        <br>
        -Kris @ What You've Read""".format(
            email_hash
        )

        common.send_simple_message(email, subject, text)

        flash("Please check your email to activate your account.")
        return redirect(url_for("main.index"))

    return render_template("index.html")


@bp.route("/activate", methods=["GET", "POST"])
def activate():
    """ Activate user account - finish the sign up process now that the email
    is verified - get user's password, do checks on it, and insert user into database
    """

    if request.method == "GET":

        # first, pull user's email and username out of hash
        hash = request.args.get("code")
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        try:
            decoded = serializer.loads(hash, salt="sign_up", max_age=3600)
        except SignatureExpired:
            flash("Activation period expired. Please sign up again.")
            return redirect(url_for("main.index"))
        except:
            flash("Error activating your account. Please sign up again below.")
            return redirect(url_for("main.index"))

        return render_template("activate.html", username=decoded[0], email=decoded[1])

    # get user's desired password, check, add account
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Your passwords did not match. Please try again.")
            return render_template("activate.html", username=username, email=email)
        if len(password) < 5:
            flash("Your password is too short. Please try again.")
            return render_template("activate.html", username=username, email=email)
        if User.query.filter_by(username=username).count() > 0:
            flash("You've already activated your account.")
            return redirect(url_for("main.index"))

        myctx = CryptContext(schemes=["pbkdf2_sha256"])
        hashed_password = myctx.hash(password)

        alphabet = string.ascii_letters + string.digits
        salt = "".join(secrets.choice(alphabet) for i in range(32))

        user = User(username, hashed_password, salt, email)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        flash("Thank you. Your account has been activated.")
        return redirect(url_for("main.settings"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    """ Let users log in. """
    if request.method == "POST":
        username = request.form["wyr_username"]
        password = request.form["wyr_password"]
        remember = request.form.getlist("remember")
        next_page = request.form["next"]

        try:
            user = User.query.filter_by(username=username).one()
        except NoResultFound:
            flash("Username does not exist.")
        else:
            myctx = CryptContext(schemes=["pbkdf2_sha256"])
            if myctx.verify(password, user.password):
                if remember:
                    login_user(user, remember=True)
                else:
                    login_user(user)

                flash("Welcome back, {}.".format(username))

            else:
                # raise ex.IncorrectPasswordException
                flash("Sorry, the password is incorrect.")

            if next_page:
                return redirect("https://www.whatyouveread.com" + next_page)

        return redirect(url_for("main.index"))

    return render_template("index.html", next_page=request.args.get("next"))


@bp.route("/logout")
def logout():
    """ Log out users. """
    logout_user()
    flash("You've been logged out.")
    return redirect(url_for("main.index"))


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """ Settings page. """
    if request.method == "POST":
        current_user.auto_close = request.form["auto_close"]
        current_user.markdown = request.form["markdown"]
        current_user.include_m_unread = request.form.get("include_m_unread", "")
        current_user.include_g_unread = request.form.get("include_g_unread", "")
        old_include_m_unread = request.form.get("old_include_m_unread", "")
        old_include_g_unread = request.form.get("old_include_g_unread", "")
        db.session.commit()

        # if user is changing pref to exclude to-read items in Mendely, delete any
        # existing Mendeley docs tagged as to-read
        if current_user.include_m_unread == 0 and old_include_m_unread == "1":
            common.remove_to_read(1)

        # if user is changing pref to exclude to-read items in Goodreads, delete any
        # existing Goodreads books tagged as to-read
        if current_user.include_g_unread == 0 and old_include_g_unread == "1":
            common.remove_to_read(2)

        # if user changed pref to include to-read items in Mendeley, set var
        # do a full update (not limited to recent items)
        if current_user.include_m_unread == 1 and old_include_m_unread == "0":
            mendeley.import_mendeley("unread_update")

        # if user changed pref to include to-read items in Mendeley, set var
        # do a full update (not limited to recent items)
        if current_user.include_g_unread == 1 and old_include_g_unread == "0":
            goodreads.import_goodreads("unread_update")

        flash("Your preferences have been updated.")
        return redirect(url_for("main.settings"))
    apps = current_user.apps.all()
    clients = Client.query.filter_by(user_id=current_user.id).all()

    return render_template("settings.html", apps=apps, clients=clients)


@bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """ Let users change password """

    if request.method == "POST":
        if request.form["submit"] == "Cancel":
            flash("Password change cancelled.")
            return redirect(url_for("main.settings"))

        current_password = request.form["wyr_current_password"]
        new_password = request.form["wyr_new_password"]
        confirm_password = request.form["wyr_confirm_password"]
        myctx = CryptContext(schemes=["pbkdf2_sha256"])

        if myctx.verify(current_password, current_user.password):
            if len(new_password) < 5:
                flash("Password is too short. Please try again.")
                return redirect(url_for("main.change_password"))
            if new_password != confirm_password:
                flash("The confirmation password did not match the new password you entered.")
                return redirect(url_for("main.change_password"))

            myctx = CryptContext(schemes=["pbkdf2_sha256"])
            hash = myctx.hash(new_password)
            current_user.password = hash
            db.session.commit()

            # send user email to confirm, allow reset of password hash for confirm change
            serializer = URLSafeSerializer(current_app.config["SECRET_KEY"])
            email_hash = serializer.dumps([current_user.email], salt="reset_password")

            to = current_user.email
            subject = "Password Change"
            text = """The password for your What You've Read account has been
            changed. If this was not you, someone has access to your account. You should
            <a href="http://www.whatyouveread.com/reset_password?code={}">reset your
            password</a> immediately.<br>
            <br>
            -Kris @ What You've Read""".format(
                email_hash
            )

            common.send_simple_message(to, subject, text)

            flash("Your password has been updated.")
            return redirect(url_for("main.settings"))
        flash("Password is incorrect.")
        return redirect(url_for("main.change_password"))
    return render_template("change_password.html")


@bp.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    """Display form to send email link to reset password; display form to reset password if user
    clicked on confirmation link."""

    if request.method == "POST":
        if request.form["send_email"] == "Cancel":
            return redirect(url_for("main.index"))

        email = request.form["email"]

        # check we have the email
        if User.query.filter_by(email=email).count() > 0:
            # generate the token, send the email, then return user to login
            serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
            email_hash = serializer.dumps([email], salt="forgot_password")

            subject = "Reset Forgotten Password"
            text = """What You've Read has received a request to reset your
            forgotten password. Please follow
            <a href="http://www.whatyouveread.com/forgot_password?reset={}">this link</a>
            to reset it.""".format(
                email_hash
            )

            common.send_simple_message(email, subject, text)

            flash(
                "An email has been sent to you. Please follow the link provided to reset your password."
            )
            return redirect(url_for("main.index"))

        else:
            flash("No account with that email exists.")
            return redirect(url_for("main.index"))

    # display form to enter email to initiate reset process
    if not request.args.get("reset"):
        return render_template("forgot_password.html")

    # otherwise, user has already clicked on confirmation link
    hash = request.args.get("reset")

    return render_template("reset_password.html", hash=hash)


@bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    """ allow user to reset password
    hash: variable emailed in link to user to confirm resetting
    """

    # process the password reset request
    if request.method == "POST":
        if request.form["submit"] == "cancel":
            flash("Password reset canceled.")
            return redirect(url_for("main.index"))

        hash = request.form["hash"]
        untimed = ""

        # use untimed version of URL serializer - user has noticed attempt to change
        # their email and is resetting password
        if request.form["untimed"] == "true":
            untimed = request.form["untimed"]
            serializer = URLSafeSerializer(current_app.config["SECRET_KEY"])
            try:
                decoded = serializer.loads(hash, salt="reset_password")
            except:
                flash("Sorry, there was an error. Please try again.")
                return redirect(url_for("main.index"))

        # use timed version - user forgot password and was sent link to reset
        else:
            serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
            try:
                decoded = serializer.loads(hash, salt="forgot_password", max_age=3600)
            except SignatureExpired:
                flash("The link has expired; password not reset.")
                return redirect(url_for("main.index"))
            except:
                flash("Sorry, there was an error. Please try again.")
                return redirect(url_for("main.index"))

        # try to update password
        try:
            user = User.query.filter_by(email=decoded[0]).one()
        except NoResultFound:
            flash("Could not find an account associated with that email address.")
            return redirect(url_for("main.index"))
        else:
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]

            if len(password) < 5:
                flash("Password is too short. Please try again.")
                return render_template("reset_password.html", hash=hash, untimed=untimed)
            if password != confirm_password:
                flash("The confirmation password did not match the new password you entered.")
                return render_template("reset_password.html", hash=hash, untimed=untimed)

            myctx = CryptContext(schemes=["pbkdf2_sha256"])
            hashed_password = myctx.hash(password)
            user.password = hashed_password
            db.session.commit()
            flash("Your password has been updated. Please use it to login.")
            return redirect(url_for("main.login"))

    if request.args.get("code"):
        return render_template("reset_password.html", hash=request.args.get("code"), untimed="true")
    return redirect(url_for("main.index"))


@bp.route("/change_email", methods=["GET", "POST"])
@login_required
def change_email():
    """ Change user email """

    if request.method == "POST":
        if request.form["submit"] == "Cancel":
            flash("Email change cancelled.")
            return redirect(url_for("main.settings"))

        new_email = request.form["new_email"]
        password = request.form["password"]

        # minimum check that it's an email:
        if "@" not in new_email:
            flash("That didn't look like an email address. Please try again.")
            return redirect(url_for("main.change_email"))

        # check if email already in use in another account
        if User.query.filter_by(email=new_email).count() > 0:
            flash("Sorry, that email address is already in use.")
            return redirect(url_for("main.change_email"))

        # verify password
        myctx = CryptContext(schemes=["pbkdf2_sha256"])
        if myctx.verify(password, current_user.password):

            # hash for confirm change
            serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
            email_hash = serializer.dumps([current_user.username, new_email], salt="change_email")

            # hash for resetting password if user didn't initiate this (change salt
            # and use regular serializer, not timed one)
            serializer2 = URLSafeSerializer(current_app.config["SECRET_KEY"])
            email_hash2 = serializer2.dumps([current_user.email], salt="reset_password")

            text = """What You've Read has received a request to change your email
            address to {}. If this was you, please follow
            <a href="http://www.whatyouveread.com/change_email?code={}">
            this link</a> to confirm.
            <br><br>
            If this was not you, someone has access to your account. You should
            <a href="http://www.whatyouveread.com/reset_password?code={}">reset your
            password</a> immediately.""".format(
                new_email, email_hash, email_hash2
            )

            common.send_simple_message(current_user.email, "Email address change", text)

            flash(
                """Please check your email at your current email address
                and follow the link provided."""
            )
            return redirect(url_for("main.settings"))

        flash("Password is incorrect.")
        return redirect(url_for("main.change_email"))

    # if this is coming from link sent to current email address, send another to new email address
    if request.args.get("code"):
        hash = request.args.get("code")
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        try:
            decoded = serializer.loads(hash, salt="change_email", max_age=3600)
        except:
            flash(
                """Error confirming your credentials. Please try again later or contact
            us if this problem continues to exist."""
            )
            return redirect(url_for("main.settings"))

        # if for some reason some other logged in user clicks the link
        if decoded[0] != current_user.username:
            flash("Username does not match. Email not changed.")
            redirect(url_for("main.index"))

        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        email_hash = serializer.dumps([current_user.username, decoded[1]], salt="change_email")

        text = """What You've Read has received a request to change your email
        address to this one. If this was you, please follow
        <a href="http://www.whatyouveread.com/change_email?confirm={}">
        this link</a> to confirm.""".format(
            email_hash
        )

        common.send_simple_message(decoded[1], "Email address change", text)

        flash(
            """Please check your email at your new email address and
        follow the link provided to confirm it."""
        )
        return redirect(url_for("main.settings"))

    # if this is coming from the link sent to confirm the change, change it
    if request.args.get("confirm"):
        hash = request.args.get("confirm")
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        try:
            decoded = serializer.loads(hash, salt="change_email", max_age=3600)
        except:
            flash(
                """Error confirming your credentials. Please try again later or contact
            us if this problem continues to exist."""
            )
            return redirect(url_for("main.settings"))

        # if for some reason some other logged in user clicks the link
        if decoded[0] != current_user.username:
            flash("Username does not match. Email not changed.")
            redirect(url_for("main.index"))

        current_user.email = decoded[1]
        db.session.commit()
        flash("Your email has been changed.")
        return redirect(url_for("main.settings"))

    # else, display the original form to request the email change
    return render_template("change_email.html")


@bp.route("/screenshots")
def screenshots():
    """ screenshots of WYR for new potential users """
    return render_template("screenshots.html")


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    """ contact me """
    if request.method == "POST":
        if current_user.is_authenticated:
            name = current_user.username
            email = current_user.email
        else:
            email = request.form["email"]
            name = request.form["name"]

        submit = request.form["submit"]
        comments = request.form["comments"]

        if submit == "Cancel":
            return redirect(url_for("main.index"))

        if comments == "":
            flash("You didn't add any comments.")
            return render_template("contact.html")

        common.send_simple_message(
            "info@whatyouveread.com",
            "Submitted comments on WYR",
            f"{name} ({email}) submitted these comments:<br>{comments}",
        )

        flash("Your comments have been sent. Thank you.")

        return redirect(url_for("main.index"))

    return render_template("contact.html")


@bp.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    """delete account, after password validation"""
    if request.method == "POST":
        confirm = request.form["delete_account"]
        if confirm == "Yes":
            current_password = request.form["wyr_current_password"]
            myctx = CryptContext(schemes=["pbkdf2_sha256"])

            if myctx.verify(current_password, current_user.password):
                User.query.filter_by(id=current_user.id).delete()
                db.session.commit()

                common.delete_orphaned_tags()
                common.delete_orphaned_authors()
                db.session.commit()

                flash("Account deleted. Sorry to see you go!")
                return redirect(url_for("main.index"))
            flash("Password incorrect.")
            return redirect(url_for("main.settings"))
        else:
            flash("Account deletion cancelled.")
            return redirect(url_for("main.settings"))
    return render_template("delete_account.html")


def get_stripe_info():
    """Get user's Stripe info."""
    if current_user.stripe_id is not None:
        donor = stripe.Customer.retrieve(current_user.stripe_id)

        # simplify object a bit, see if user has current subscription to plan
        try:
            subscription = donor.subscriptions["data"][0]
        except IndexError:
            subscription = ""

        # drop everything else from donor
        # TODO

    else:
        donor = ""
        subscription = ""

    return donor, subscription


@bp.route("/donate")
@login_required
def donate():
    """ get user stripe info and send to donate page"""
    stripe_keys = current_app.config["STRIPE_KEYS"]
    donor, subscription = get_stripe_info()

    return render_template(
        "donate.html", key=stripe_keys["publishable_key"], donor=donor, subscription=subscription
    )


@bp.route("/cancel_donation", methods=["GET", "POST"])
@login_required
def cancel_donation():
    """ let user cancel a donation """
    stripe_keys = current_app.config["STRIPE_KEYS"]

    if request.method == "POST":
        donor, subscription = get_stripe_info()

        if request.form["cancel_next_donation"] == "Yes":
            # cancel it
            subscription = stripe.Subscription.retrieve(subscription.id)
            subscription.delete()
            flash("Your scheduled donation has been cancelled.")
        else:
            flash("Your scheduled donation has NOT been cancelled.")

        return render_template(
            "donate.html",
            key=stripe_keys["publishable_key"],
            donor=donor,
            subscription=subscription,
        )

    return render_template("cancel_donation.html")


@bp.route("/charge", methods=["GET", "POST"])
@login_required
def charge():
    """Charge user's donation to their payment method."""
    stripe_keys = current_app.config["STRIPE_KEYS"]
    if request.method == "POST":

        # Get the credit card details submitted by the form
        token = request.form["stripeToken"]
        plan = request.form["plan"]
        sub_id = request.form["sub_id"]
        customer_id = request.form["customer_id"]

        # Create the charge on Stripe's servers - this will charge the user's card
        try:
            # if current subscription, update it, else create new customer (and subscription)
            if sub_id != "":
                customer = stripe.Customer.retrieve(customer_id)
                subscription = stripe.Subscription.retrieve(sub_id)
                if plan == "0":  # TODO: I'm fairly certain I can delete this if
                    # cancel it
                    subscription.delete()
                else:
                    # update it
                    subscription.plan = plan
                    subscription.save()
            else:
                customer = stripe.Customer.create(email=current_user.email, plan=plan, source=token)
        except stripe.error.CardError:
            flash("Sorry, your card has been declined. Please try again.")
            return redirect(url_for("main.donate"))
        except stripe.error.RateLimitError:
            # Too many requests made to the API too quickly
            flash("Sorry, the server has been overloaded. Please try again in a moment.")
            return redirect(url_for("main.donate"))
        except stripe.error.InvalidRequestError:
            # Invalid parameters were supplied to Stripe's API
            flash("Sorry, we have made an error(1). Please try again later.")
            return redirect(url_for("main.donate"))
        except stripe.error.AuthenticationError:
            # Authentication with Stripe's API failed
            # (maybe you changed API keys recently)
            flash("Sorry, we have made an error(2). Please try again later.")
            return redirect(url_for("main.donate"))
        except stripe.error.APIConnectionError:
            # Network communication with Stripe failed
            flash("Sorry, we have made an error(3). Please try again later.")
            return redirect(url_for("main.donate"))
        except stripe.error.StripeError:
            # Display a very generic error to the user, and maybe send yourself an email
            pass
        except Exception:
            # Something else happened, completely unrelated to Stripe
            flash("Sorry, we have made an error(4). Please try again later.")
            return redirect(url_for("main.donate"))

        current_user.stripe_id = customer.id
        db.session.commit()

        flash(
            """Thanks for the donation. A receipt will be emailed to you.
            If you do not get it, contact me."""
        )

    donor, subscription = get_stripe_info()

    return render_template(
        "donate.html", key=stripe_keys["publishable_key"], donor=donor, subscription=subscription
    )


@bp.route("/donate_paypal")
def paypal():
    return render_template("donate_paypal.html")


####################
# THIRD PARTY APPS #
####################

# from the user's perspective


@bp.route("/revoke", methods=["GET", "POST"])
@login_required
def revoke():
    """Revoke app authorization."""
    if request.method == "GET":
        app_id = request.args.get("app_id")
        app = Client.query.filter_by(client_id=app_id).one()
        return render_template("revoke_app.html", app=app)

    app_id = request.form["app_id"]
    app_name = request.form["app_name"]
    confirm = request.form["revoke"]

    if confirm == "Yes":
        app = current_user.apps.filter_by(client_id=app_id).one()
        current_user.apps.remove(app)
        db.session.commit()
        message = f"Authorization for {app_name} has been revoked."
    else:
        message = "Revoke authorization cancelled."

    flash(message)
    return redirect(url_for("main.settings"))


# handle 404 - this was throwing errors where it shouldn't, so disabled
# @bp.errorhandler(404)
# def page_not_found(e):
#     flash("Sorry, that page wasn't found.")
#     return redirect(url_for('index'))


@bp.errorhandler(413)
def file_too_big(e):
    flash("Sorry, that file is too big.")
    return render_template("import.html")
