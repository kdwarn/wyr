import pytest

from app import models, common, db
from app import exceptions as ex
from sqlalchemy.orm.exc import NoResultFound

# Testing the functions in common.py, assuming authors in the final format of
# a list of dictionaries with keys first_name and last_name


########################
# TAG HELPER FUNCTIONS #
########################

# get_user_tags()


def test_get_user_tags(user1):
    """get_user_tags gets all of the user's tags."""

    tags = common.get_user_tags(user1)

    assert len(tags) == 5


def test_get_user_tags_no_tags(user0):

    tags = common.get_user_tags(user0)

    assert not tags


# get_user_tag()


def test_get_user_tag(user1):
    """get_user_tag() gets the correct tag."""

    tag = common.get_user_tag(user1, "tag0")

    assert tag.name == "tag0"


def test_get_user_tag_raises_ex(user1):
    """get_user_tag() rasies exception if no user tag by provided name."""

    with pytest.raises(NoResultFound):
        common.get_user_tag(user1, "tag5")


# delete_orphaned_tags()


def test_delete_orphaned_tags0(user1):
    """Orphaned tags are deleted when tags are removed manually."""

    doc = user1.documents.first()

    doc.tags.clear()
    db.session.commit()

    common.delete_orphaned_tags()
    db.session.commit()

    tags = models.Tags.query.all()

    assert len(tags) == 4 and "tag1" not in tags


###########################
# AUTHOR HELPER FUNCTIONS #
###########################


def test_get_user_authors1(user1):
    """get_user_authors() returns all user's authors."""

    authors = common.get_user_authors(user1)

    assert len(authors) == 4


def test_get_user_authors2(user0):
    """get_user_authors() returns no authors if user has none."""

    authors = common.get_user_authors(user0)

    assert not authors


def test_get_user_author1(user1):
    """get_user_author() returns correct author."""

    author = common.get_user_author(user1, "Jane", "Johnson")

    assert author.id == 4


def test_get_user_author2_raises_ex(user1):
    """get_user_author() raises exception if author in user's authors."""

    with pytest.raises(NoResultFound):
        common.get_user_author(user1, "Kris", "Warner")


###################
# ADDING DOCUMENTS#
###################


def test_add_no_title_raises_ex(user0):
    content = {"title": ""}
    with pytest.raises(ex.NoTitleException):
        common.add_item(content, user0)


def test_duplicate_link_raises_ex(user0):

    content1 = {"title": "Test", "link": "http://whatyouveread.com/1"}
    content2 = {"title": "Test2", "link": "http://whatyouveread.com/1"}

    common.add_item(content1, user0)

    with pytest.raises(ex.DuplicateLinkException):
        common.add_item(content2, user0)


def test_http_added_to_link(user0):

    content1 = {"title": "Test", "link": "www.whatyouveread.com/1"}

    common.add_item(content1, user0)

    doc = user0.documents.first()

    assert doc.link == "http://www.whatyouveread.com/1"


def test_add_unexpected_read_value_defaults_to_1(user0):
    content = {"title": "Test", "read": 3}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.read == 1


def test_add_no_read_value_defaults_to_1(user0):
    content = {"title": "Test", "read": ""}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.read == 1


def test_add_str_read_value_converted_to_int1(user0):
    content = {"title": "Test", "read": "1"}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.read == 1


def test_add_str_read_value_converted_to_int2(user0):
    content = {"title": "Test", "read": "0"}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.read == 0


def test_add_one_minimal(user0):
    content = {"title": "Test"}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.title == "Test"


def test_add_two_minimal(user0):
    content = [{"title": "Test"}, {"title": "Test2"}]
    for item in content:
        common.add_item(item, user0)
    doc = user0.documents.all()
    assert len(doc) == 2


def test_add_four_full(user0, four_items):
    for item in four_items:
        common.add_item(item, user0)

    doc = user0.documents.all()
    assert len(doc) == 4


def test_add_wrong_year_format_ok1(user0):
    content = {"title": "Test", "year": "12"}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.year == "12"


def test_add_wrong_year_format_ok2(user0):
    content = {"title": "Test", "year": "Smith; Jane"}
    common.add_item(content, user0)
    doc = user0.documents.first()
    assert doc.year == "Smith; Jane"


###############
# EDITING DOCS#
###############


def test_edit_not_user_doc_raises_ex(user0, user1, four_items):
    content = {"id": "1", "title": "Test"}  # not a user0 doc

    with pytest.raises(ex.NotUserDocException):
        common.edit_item(content, user0)


def test_edit_no_title_raises_ex(user1):

    content = {"id": "1", "title": ""}

    with pytest.raises(ex.NoTitleException):
        common.edit_item(content, user1)


def test_http_added_to_link_in_edit(user1):

    content = {"id": "1", "title": "Test", "link": "example.com"}

    common.edit_item(content, user1)

    doc = user1.documents.first()

    assert doc.link == "http://example.com"


def test_edit_no_read_value_defaults_to_1(user1):

    content = {
        "id": "1",
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0", "tag1"],
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
        ],
        "year": "2018",
        "notes": "This is a note.",
        "read": "",
    }

    common.edit_item(content, user1)
    doc = user1.documents.first()
    assert doc.read == 1


def test_edit_unexpected_read_value_defaults_to_1(user1):
    """Read value other than 0 or 1 defaults to 1."""

    content = {
        "id": "1",
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0", "tag1"],
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
        ],
        "year": "2018",
        "notes": "This is a note.",
        "read": "3",
    }

    common.edit_item(content, user1)
    doc = user1.documents.first()
    assert doc.read == 1


def test_edit_str_read_value_converted_to_int1(user1):
    """Read value of '0' converted to 0."""

    content = {
        "id": "1",
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0", "tag1"],
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
        ],
        "year": "2018",
        "notes": "This is a note.",
        "read": "0",
    }

    common.edit_item(content, user1)
    doc = user1.documents.first()
    assert doc.read == 0


def test_edit_str_read_value_converted_to_int2(user1):
    """Read value of '1' converted to 1."""

    content = {
        "id": "1",
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0", "tag1"],
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
        ],
        "year": "2018",
        "notes": "This is a note.",
        "read": "1",
    }

    common.edit_item(content, user1)
    doc = user1.documents.first()
    assert doc.read == 1


# tags


def test_edit_remove_one_tag(user0, three_items_tags_only):
    """ Removing one tag works properly."""

    for item in three_items_tags_only:
        common.add_item(item, user0)

    content = {"id": "1", "title": "Test", "tags": ["tag0"]}

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert doc.tags[0].name == "tag0" and len(doc.tags) == 1


def test_edit_remove_all_tags(user0, three_items_tags_only):
    """ Removing all tags works properly."""

    for item in three_items_tags_only:
        common.add_item(item, user0)

    content = {"id": "1", "title": "Test", "tags": []}

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert len(doc.tags) == 0


def test_edit_add_one_tag(user0, three_items_tags_only):
    """Adding one tag works properly - count."""

    for item in three_items_tags_only:
        common.add_item(item, user0)

    content = {"id": "1", "title": "Test", "tags": ["tag0", "tag1", "tag2"]}

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert len(doc.tags) == 3


def test_edit_only_one_tag_correct_text(user0, three_items_tags_only):
    """Adding one tag works properly - value."""

    for item in three_items_tags_only:
        common.add_item(item, user0)

    content = {"id": "1", "title": "Test", "tags": ["tag0", "tag1", "tag2"]}

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert doc.tags[2].name == "tag2"


def test_edit_add_tag_no_previous_tags(user0, three_items_tags_only):
    """Add one tag to doc with no previous tags."""

    for item in three_items_tags_only:
        common.add_item(item, user0)

    content = {"id": "3", "title": "Test", "tags": ["new tag"]}

    common.edit_item(content, user0)

    doc = user0.documents.filter(models.Documents.id == 3).one()

    assert len(doc.tags) == 1 and doc.tags[0].name == "new tag"


def test_delete_orphaned_tags1(user1):
    """Orphaned tags are deleted when item is deleted."""

    doc = user1.documents.first()

    common.delete_item(doc.id, user1)

    tags = common.get_user_tags(user1)

    assert len(tags) == 4 and "tag1" not in tags


def test_delete_orphaned_tags2(user1):
    """Orphaned tags are deleted when item is edited."""

    content = {
        "id": 1,
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0"],
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
        ],
        "year": "2018",
        "notes": "This is a note.",
        "read": 1,
    }

    common.edit_item(content, user1)

    tags = common.get_user_tags(user1)

    assert len(tags) == 4 and "tag1" not in tags


# authors


def test_edit_add_one_author(user0, three_items_authors_only):
    """Adding one author works properly."""

    for item in three_items_authors_only:
        common.add_item(item, user0)

    content = {
        "id": "1",
        "title": "Test",
        "authors": [
            {"last_name": "Smith", "first_name": "Joe"},
            {"last_name": "Smith", "first_name": "Jane"},
            {"last_name": "Williams", "first_name": "Regina"},
        ],
    }

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert (
        len(doc.authors) == 3
        and doc.authors[2].first_name == "Regina"
        and doc.authors[2].last_name == "Williams"
    )


def test_edit_only_one_author_correct_text(user0, three_items_authors_only):
    """Editing one author results in correct author name."""

    for item in three_items_authors_only:
        common.add_item(item, user0)

    content = {
        "id": "1",
        "title": "Test",
        "authors": [{"last_name": "Smith", "first_name": "Jane"}],
    }

    common.edit_item(content, user0)

    doc = user0.documents.first()

    assert doc.authors[0].last_name == "Smith" and doc.authors[0].first_name == "Jane"


def test_edit_add_author_no_previous_authors(user0, three_items_authors_only):
    """Adding an author to a doc that previously had no authors."""

    for item in three_items_authors_only:
        common.add_item(item, user0)

    content = {
        "id": "3",
        "title": "Test",
        "authors": [{"last_name": "Smith", "first_name": "Jane"}],
    }

    common.edit_item(content, user0)

    doc = user0.documents.filter(models.Documents.id == 3).one()

    assert (
        len(doc.authors) == 1
        and doc.authors[0].first_name == "Jane"
        and doc.authors[0].last_name == "Smith"
    )


def test_delete_orphaned_authors1(flask_client, user1):
    """Orphaned authors are deleted when item is deleted."""

    doc = user1.documents.first()

    common.delete_item(doc.id, user1)

    authors = common.get_user_authors(user1)

    assert len(authors) == 3


def test_delete_orphaned_authors2(user1):
    """Orphaned authors are deleted when item is edited."""

    content = {
        "id": 1,
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": ["tag0", "tag1"],
        "authors": [{"last_name": "Smith", "first_name": "Jane"}],
        "year": "2018",
        "notes": "This is a note.",
        "read": 1,
    }

    common.edit_item(content, user1)

    authors = common.get_user_authors(user1)

    assert len(authors) == 3


# multiple different edits


def test_edit_remove_all_tags_and_authors(user1):
    """ Removing all tags and authors works properly."""

    content = {
        "id": "1",
        "title": "Test",
        "link": "http://whatyouveread.com/1",
        "tags": [],
        "authors": [],
        "year": "2018",
        "notes": "This is a note.",
        "read": 1,
    }

    common.edit_item(content, user1)

    doc = user1.documents.first()

    assert len(doc.tags) == 0 and len(doc.authors) == 0


def test_edit_all(user1):
    """Editing everything works properly."""

    content = {
        "id": "1",
        "title": "Test Now",
        "link": "http://whatyouveread.com/5",
        "tags": ["tag2"],
        "authors": [{"last_name": "Williams", "first_name": "Regina"}],
        "year": "2017",
        "notes": "This is an edited note.",
        "read": 0,
    }

    common.edit_item(content, user1)

    doc = user1.documents.first()

    assert (
        doc.title == "Test Now"
        and doc.link == "http://whatyouveread.com/5"
        and len(doc.tags) == 1
        and doc.tags[0].name == "tag2"
        and len(doc.authors) == 1
        and doc.authors[0].first_name == "Regina"
        and doc.authors[0].last_name == "Williams"
        and doc.year == "2017"
        and doc.notes == "This is an edited note."
        and doc.read == 0
    )


def test_edit_clear_all_but_title(user1):
    """Removing everything but title works properly."""

    content = {
        "id": "1",
        "title": "Test Now",
        "link": "",
        "tags": [],
        "authors": [],
        "year": "",
        "notes": "",
        "read": 0,
    }

    common.edit_item(content, user1)

    doc = user1.documents.first()

    assert (
        doc.title == "Test Now"
        and doc.link == ""
        and len(doc.tags) == 0
        and len(doc.authors) == 0
        and doc.year == ""
        and doc.notes == ""
        and doc.read == 0
    )


def test_db_is_empty_after_previous_tests(flask_client):
    docs = models.Documents.query.all()
    assert not docs


################
# DELETING DOCS#
################


def test_delete_item(user1):
    """delete_item() works."""

    doc = user1.documents.first()

    common.delete_item(doc.id, user1, source="native")

    assert user1.documents.count() == 3


def test_delete_not_user_doc_raises_ex(user1, user2):
    """delete_item() only deletes user's own docs."""

    with pytest.raises(ex.NotUserDocException):
        common.delete_item(5, user1)


def test_delete_doc_that_does_not_exist_raises_ex(flask_client, user4):
    """delete_item() raises exception when trying to delete doc that doesn't exist."""

    with pytest.raises(ex.NotUserDocException):
        common.delete_item(5, user4)


################
# GETTING DOCS #
################


def test_get_all_docs1(flask_client, user4):
    docs = common.get_docs(user4)
    assert len(docs) == 4


def test_get_all_docs2(flask_client, user0):
    docs = common.get_docs(user0)
    assert not docs


def test_get_all_docs3(flask_client, user0, user4):
    """get_docs() only gets docs for user we pass in function."""
    docs = common.get_docs(user0)
    assert not docs


def test_get_read_docs(flask_client, user4):
    docs = common.get_docs(user4, read_status="read")
    assert len(docs) == 1


def test_get_to_read_docs(flask_client, user4):
    docs = common.get_docs(user4, read_status="to-read")
    assert len(docs) == 3


def test_get_docs_by_tag1(flask_client, user4):
    docs = common.get_docs(user4, read_status="read", tag="tag0")
    assert len(docs) == 1


def test_gets_docs_by_tag2(flask_client, user4):
    docs = common.get_docs(user4, read_status="to-read", tag="tag2")
    assert len(docs) == 2


def test_get_docs_by_tag3(flask_client, user4):
    docs = common.get_docs(user4, tag="tag0")
    assert len(docs) == 2


def test_get_docs_by_tag4(flask_client, user4):
    """get_docs returns no docs if user has no docs with that tag."""
    docs = common.get_docs(user4, tag="tag5")
    assert not docs


def test_get_docs_by_tag5(flask_client, user4, user5):
    """Only docs for passed user are returned (tag4 in both user4 and user5 docs)."""
    docs = common.get_docs(user4, tag="tag4")
    assert len(docs) == 1


def test_get_docs_by_author1(flask_client, user4):
    docs = common.get_docs(user4, author_id=1)
    assert len(docs) == 1


def test_get_docs_by_author2(flask_client, user4):
    docs = common.get_docs(user4, author_id=3)
    assert len(docs) == 1


def test_get_docs_by_author3(flask_client, user4, user5):
    """Can't access other user's authors."""
    docs = common.get_docs(user4, author_id=5)
    assert not docs


def test_get_docs_by_bunch1(flask_client, user6):

    docs = common.get_docs(user6, bunch="bunch 1")

    assert len(docs) == 4


def test_get_docs_by_bunch2(flask_client, user6):

    docs = common.get_docs(user6, bunch="bunch 2")
    assert len(docs) == 2


def test_get_docs_by_bunch3(flask_client, user6):
    "Undefined bunch."

    with pytest.raises(ex.NoBunchException):
        common.get_docs(user6, bunch="nobunch")
