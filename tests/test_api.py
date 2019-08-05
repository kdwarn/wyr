"""
    TODO:
        - test that client id matches that parameter in the decoded authorization_code
        - test that cookies/sessions are not sent in responses (shouldn't be)
        - all error testing for document() and documents()
        - integration(?) testing - the whole process from authorization to adding/editing/deleting/
            getting doc(s) (new section at bottom)
        - disable email to WYR about client registration unless explicitly enabled? (to avoid
          emails while testing) (haven't set this up yet in api.py)
        - testing editing client info
"""

import datetime
from urllib.parse import urlparse, parse_qs

import jwt
import pytest

from app import api, models


###################
# CLIENT CREATION #
###################

# for ad-hoc creation of client app
valid_client_vars = {
    "submit": "register",
    "name": "Tester App Ad Hoc",
    "description": "This is a test client app",
    "callback_url": "https://www.test.com",
}


def test_dev_app_fixture_info(dev_app, developer1):
    """ Test that the dev_app fixture was created properly. """
    client = models.Client.query.first()

    assert (
        client.user_id == developer1.id
        and client.name == "Tester App 1"
        and client.description == "Testing app development"
        and client.callback_url == "https://www.whatyouveread.com/example"
    )


def test_create_client_redirect_log_in_page(flask_client, user3):
    """Client registration takes developer to main page if not logged in."""
    response = flask_client.post("/api/clients", data=valid_client_vars, follow_redirects=True)
    clients = models.Client.query.all()

    assert b"Welcome!" in response.data and len(clients) == 0


def test_create_client_cancelled(flask_client, user4):
    """ Test cancel client registration."""
    response = flask_client.post(
        "/api/clients",
        data=dict(
            submit="cancel",
            name="Test",
            description="This is a test client app",
            callback_url="https://www.test.com",
        ),
        follow_redirects=True,
    )
    clients = models.Client.query.all()

    assert b"Client registration canceled." in response.data and len(clients) == 0


@pytest.mark.parametrize(
    "name, description, callback_url",
    [
        ("", "a simple app", "https://example.com"),
        ("Mobile WYR", "", "https://example.com"),
        ("Mobile WYR", "a simple app", ""),
    ],
)
def test_create_client_error1(flask_client, user4, name, description, callback_url):
    """ Developer returned to registration page if any form data missing."""
    response = flask_client.post(
        "/api/clients",
        data=dict(submit="register", name=name, description=description, callback_url=callback_url),
        follow_redirects=True,
    )
    clients = models.Client.query.all()

    assert b"Please complete all required fields." in response.data and len(clients) == 0


def test_create_client_error2(flask_client, user4):
    """ Callback_url must be HTTPS."""
    response = flask_client.post(
        "/api/clients",
        data=dict(
            submit="register",
            name="Test",
            description="This is a test client app",
            callback_url="http://www.test.com",
        ),
        follow_redirects=True,
    )
    clients = models.Client.query.all()

    assert b"The callback URL must use HTTPS." in response.data and len(clients) == 0


def test_create_client_sucessful1(flask_client, developer1):
    """ Created client shows in the database."""
    flask_client.post("/api/clients", data=valid_client_vars, follow_redirects=True)
    clients = models.Client.query.all()

    assert len(clients) == 1


def test_create_client_sucessful2(flask_client, developer1):
    """ Proper response is given after client created and is listed in apps. """
    response = flask_client.post("/api/clients", data=valid_client_vars, follow_redirects=True)

    assert b"Client registered" in response.data and b"Tester App Ad Hoc" in response.data


def test_create_client_sucessful3(flask_client, developer1, dev_app):
    """ A second created client shows in the database."""
    flask_client.post("/api/clients", data=valid_client_vars, follow_redirects=True)
    clients = models.Client.query.all()

    assert len(clients) == 2


def test_create_client_sucessful4(flask_client, developer1, dev_app):
    """ A second client created is listed in apps. """
    response = flask_client.post("/api/clients", data=valid_client_vars, follow_redirects=True)

    assert b"Tester App 1" in response.data and b"Tester App Ad Hoc" in response.data


####################
# CREATING TOKENS #
####################

# not specific to authorization code or access token


def test_create_token1(user6):
    """ Token created properly - decoding works (without verification). """
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = api.create_token(user6, 1, expiration)
    decoded = jwt.decode(code, verify=False)

    assert decoded["username"] == "tester6"


def test_decode_token_raises_ex_with_bad_salt(user6, dev_app):
    """ Not using the correct salt will raise exception. """
    code = api.create_token(user6, dev_app.client_id)

    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        jwt.decode(code, "bad_salt")


############################################################
# CHECKING TOKINS, INCLUDING THE @TOKEN_REQUIRED DECORATOR #
############################################################

# calling check_token here partly as a way to test @token_required


def test_check_token1(flask_client, user8, dev_app):
    """ If valid token supplied, client receives message that the token works."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/check_token",
        headers={"authorization": "Bearer " + access_token},
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert (
        response.status_code == 200
        and json_data["status"] == "Ok"
        and json_data["message"] == "Success! The token works."
    )


def test_check_token_returns_error1(flask_client):
    """ If token not provided in call to check_token(), error provided to client. """
    response = flask_client.get(
        "/api/check_token", headers={"authorization": "Bearer "}, follow_redirects=True
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 43


def test_check_token_returns_error2(flask_client):
    """
    @token_required should return error if authorization header not properly formatted.
    """
    response = flask_client.get(
        "/api/check_token",
        headers={"authorization": "Bearer" + "therewasnospaceafterBearer"},
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 41


def test_check_token_returns_error3(flask_client, user8):
    """
    @token_required returns error if the user has not authorized the app or has revoked authorization. 
    """
    access_token = api.create_token(user8, "123")
    response = flask_client.get(
        "/api/check_token",
        headers={"authorization": "Bearer " + access_token},
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 20


def test_check_token_returns_error4(flask_client):
    """
    Check that manipulated/incomplete token returns error resulting from DecodeError exception.
    """
    assert False


##################################################
# USER AUTHORIZATION OF APP, AUTHORIZATION CODES #
##################################################


def test_app_authorization_get1(flask_client, user1):
    """ User is redirected to login page if they are not logged in."""
    response = flask_client.get(
        "/api/authorize",
        query_string={"client_id": "1", "response_type": "not_code"},
        follow_redirects=True,
    )

    assert b"Welcome!" in response.data


@pytest.mark.parametrize("client_id, response_type", [("1", "not_code"), ("1", "")])
def test_app_authorization_get2(flask_client, user6, client_id, response_type):
    """ **response_type** passed must be set to 'code'."""
    response = flask_client.get(
        "/api/authorize",
        query_string={"client_id": "1", "response_type": "not_code"},
        follow_redirects=True,
    )
    assert b"Query parameter response_type must be set to " in response.data


@pytest.mark.parametrize("client_id, response_type", [("500", "code"), ("", "code")])
def test_app_authorization_get3(flask_client, user6, client_id, response_type):
    """ *client_id* must be id of a registered client."""
    response = flask_client.get(
        "/api/authorize",
        query_string={"client_id": "500", "response_type": "code"},
        follow_redirects=True,
    )

    assert b"No third-party app found matching request. Authorization failed." in response.data


def test_app_authorization_get4(flask_client, user6, dev_app):
    """User presented with authorization form if all checks pass."""
    response = flask_client.get(
        "/api/authorize",
        query_string={"client_id": dev_app.client_id, "response_type": "code"},
        follow_redirects=True,
    )

    assert b"Authorize App" in response.data


def test_app_authorization_post1(flask_client, user6, dev_app):
    """callback_url and code and state passed into redirect."""
    response = flask_client.post(
        "/api/authorize",
        data=dict(submit="Yes", client_id=dev_app.client_id, state="xyz"),
        follow_redirects=False,
    )

    assert (
        dev_app.callback_url in response.headers["Location"]
        and "code" in response.headers["Location"]
        and "state" in response.headers["Location"]
    )


#################
# ACCESS TOKENS #
#################


def test_get_access_token1(flask_client, user6, dev_app):
    """ Getting an access token works properly. """
    # create authorization code, which the client would have received via authorize()
    code = api.create_token(user6, dev_app.client_id)
    response = flask_client.post(
        "/api/token",
        data=dict(client_id=dev_app.client_id, grant_type="authorization_code", code=code),
        follow_redirects=True,
    )
    access_token = jwt.decode(response.get_json()["access_token"], user6.salt)

    assert (
        response.status_code == 200
        and response.headers["Cache-Control"] == "no-store"
        and response.headers["Pragma"] == "no-cache"
        and response.is_json
        and access_token["username"] == "tester6"
    )


@pytest.mark.parametrize("grant_type", [("authorizationcode"), ("")])
def test_get_access_token_error1(flask_client, user6, dev_app, grant_type):
    """ Return error if grant_type != authorization_code """
    code = api.create_token(user6, dev_app.client_id)
    response = flask_client.post(
        "/api/token",
        data=dict(client_id=dev_app.client_id, grant_type=grant_type, code=code),
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 400 and json_data["error"] == 25


def test_get_access_token_error2(flask_client, user6, dev_app):
    """Code can't be manipulated."""
    code = "thisisabadcode"
    response = flask_client.post(
        "/api/token",
        data=dict(client_id=dev_app.client_id, grant_type="authorization_code", code=code),
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 23


def test_get_access_token_error3(flask_client, user6, dev_app):
    """ Code cannot be expired """
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=-2)
    code = api.create_token(user6, dev_app.client_id, expiration)
    response = flask_client.post(
        "/api/token",
        data=dict(client_id=dev_app.client_id, grant_type="authorization_code", code=code),
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 22


def test_get_access_token_error4(flask_client, user6, dev_app):
    """User should get error if no matching client found."""
    code = api.create_token(user6, "2")
    response = flask_client.post(
        "/api/token",
        data=dict(client_id="2", grant_type="authorization_code", code=code),
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 404 and json_data["error"] == 2


def test_get_access_token_error6(flask_client, user6, dev_app):
    """User should get error if provided client_id does not match client_id in token."""
    code = api.create_token(user6, "2")
    response = flask_client.post(
        "/api/token",
        data=dict(client_id=dev_app.client_id, grant_type="authorization_code", code=code),
        follow_redirects=True,
    )
    json_data = response.get_json()

    assert response.status_code == 403 and json_data["error"] == 26


#######################
# PROTECTED RESOURCES #
#######################
# @pytest.mark.now
# def test_auth_header_in_get_document(flask_client, user8, dev_app):

#     access_token = api.create_token(user8, dev_app.client_id)
#     response = flask_client.get("/api/documents/1",
#                                 headers={'authorization': 'Bearer ' + access_token})

#     json_data = response.get_json()

#     print(json_data)
#     assert False


@pytest.mark.now1
def test_document_get1(flask_client, user8, dev_app):
    """document() GET should return all fields correctly."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents/1", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert (
        response.status_code == 200
        and json_data["title"] == "First user doc"
        and json_data["link"] == "http://whatyouveread.com/1"
        and json_data["year"] == "2018"
        and json_data["created"] == str(datetime.datetime.utcnow().date())
        and json_data["authors"][0]["first_name"] == "Joe"
        and json_data["authors"][0]["last_name"] == "Smith"
        and json_data["authors"][0]["id"] == 1
        and json_data["authors"][1]["first_name"] == "Jane"
        and json_data["authors"][1]["last_name"] == "Smith"
        and json_data["authors"][1]["id"] == 2
        and "tag0" in json_data["tags"]
        and "tag1" in json_data["tags"]
        and json_data["notes"] == "This is a note."
    )


def test_document_get_error1(flask_client, user8, dev_app):
    """User should get error if no item found with ID provided."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents/10", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert response.status_code == 404 and json_data["error"] == 3


def test_document_put1(flask_client, user8, dev_app):
    """document() PUT should edit one document."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.put(
        "/api/documents/1",
        headers={"authorization": "Bearer " + access_token},
        json={
            "title": "new title",  # only change
            "link": "http://whatyouveread.com/1",
            "tags": ["tag0", "tag1"],
            "authors": [
                {"last_name": "Smith", "first_name": "Joe"},
                {"last_name": "Smith", "first_name": "Jane"},
            ],
            "year": "2018",
            "notes": "This is a note.",
            "read": 1,
        },
    )
    json_data = response.get_json()

    # have to do it this way because session is no longer available
    doc1 = models.Documents.query.filter_by(id=1).one()

    assert (
        response.status_code == 200
        and json_data["message"] == "Item edited."
        and doc1.title == "new title"
        and doc1.link == "http://whatyouveread.com/1"
        and doc1.year == "2018"
        and len(doc1.authors) == 2
        and len(doc1.tags) == 2
        and doc1.notes == "This is a note."
        and doc1.read == 1
    )


def test_document_put_error1(flask_client, user8, dev_app):
    """ Client should not be able to edit non-WYR item."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.put(
        "/api/documents/3",
        headers={"authorization": "Bearer " + access_token},
        json={
            "title": "Fourth user doc",
            "link": "",
            "tags": [],
            "authors": [],
            "year": "",
            "notes": "",
            "read": 1,
        },  # only change
    )
    json_data = response.get_json()

    assert json_data["error"] == 64


def test_document_put_error2(flask_client, user8, dev_app):
    """ Client should receive error if document id not located in collection."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.put(
        "/api/documents/5", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert json_data["error"] == 3


def test_document_put_error3(flask_client, user3, user8, dev_app):
    """ User should not be able to edit another user's document."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.put(
        "/api/documents/1", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert json_data["error"] == 3


def test_document_put_error4(flask_client, user8, dev_app):
    """User's client should receive error if no title supplied in edit request."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.put(
        "/api/documents/2",
        headers={"authorization": "Bearer " + access_token},
        json={
            "title": "",
            "link": "",
            "tags": [],
            "authors": [],
            "year": "",
            "notes": "",
            "read": 0,
        },
    )
    json_data = response.get_json()

    assert json_data["error"] == 62


def test_document_delete1(flask_client, user8, dev_app):
    """document() DELETE should delete one item."""
    doc = user8.documents.first()
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.delete(
        "/api/documents/" + str(doc.id), headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    # have to do it this way because session is no longer available
    docs = models.Documents.query.filter_by(user_id=user8.id).all()

    assert (
        response.status_code == 200 and json_data["message"] == "Item deleted." and len(docs) == 3
    )


def test_document_delete_error3(flask_client, user8, dev_app):
    """Client should not be able to delete non-WYR item."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.delete(
        "/api/documents/3", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert json_data["error"] == 65


def test_document_delete_error4(flask_client, user8, dev_app):
    """User's client should receive error if document id not located in collection."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.delete(
        "/api/documents/5", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert json_data["error"] == 3


def test_document_delete_error5(flask_client, user3, user8, dev_app):
    """User's client should not be able to delete another user's document."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.delete(
        "/api/documents/1", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert json_data["error"] == 3


def test_get_all_docs(flask_client, user8, dev_app):
    """ documents() GET returns all user's documents."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    # print(json.dumps(json_data, indent=4))
    assert len(json_data) == 4


def test_get_all_read_docs(flask_client, user8, dev_app):
    """If client requests read docs, those should be returned."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"read_status": "read"},
    )
    json_data = response.get_json()

    assert len(json_data) == 1


def test_get_all_to_read_docs(flask_client, user8, dev_app):
    """If client requests read docs, those should be returned."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"read_status": "to-read"},
    )
    json_data = response.get_json()

    assert len(json_data) == 3


def test_get_docs_read_status_error(flask_client, user8, dev_app):
    """An improper read_status should return an error"""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"read_status": "toread"},
    )
    json_data = response.get_json()

    assert response.status_code == 400 and json_data["error"] == 66


def test_get_docs_by_tag1(flask_client, user8, dev_app):
    """Should return only docs with provided tag."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"tag": "tag0"},
    )
    json_data = response.get_json()

    assert response.status_code == 200 and len(json_data) == 2


def test_get_docs_by_non_existent_tag(flask_client, user8, dev_app):
    """Error should be returned if no docs found matching supplied tag."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"tag": "not a tag"},
    )
    json_data = response.get_json()

    assert response.status_code == 404 and json_data["error"] == 67


def test_get_docs_by_non_existent_author_id(flask_client, user8, dev_app):
    """Error should be returned if no docs found matching supplied author_id."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"author_id": "10"},
    )
    json_data = response.get_json()

    assert response.status_code == 404 and json_data["error"] == 67


def test_get_docs_by_non_existent_bunch(flask_client, user8, dev_app):
    """Error should be returned if no docs found matching supplied bunch."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.get(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        query_string={"bunch": "not a bunch"},
    )
    json_data = response.get_json()

    assert response.status_code == 404 and json_data["error"] == 87


@pytest.mark.now
def test_documents_post1(flask_client, user8, dev_app):
    """documents POST is successful with adding a new document."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.post(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        json={"title": "new doc title"},
    )
    json_data = response.get_json()
    docs = models.Documents.query.filter_by(user_id=user8.id).all()

    assert (
        response.status_code == 201
        and json_data["message"] == "Item added."
        and len(docs) == 5
        and docs[4].title == "new doc title"
    )


def test_documents_post_error1(flask_client, user8, dev_app):
    """User should be given error if no title providing when adding a new item."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.post(
        "/api/documents", headers={"authorization": "Bearer " + access_token}, json={"title": ""}
    )
    json_data = response.get_json()
    docs = models.Documents.query.filter_by(user_id=user8.id).all()

    assert response.status_code == 400 and json_data["error"] == 82 and len(docs) == 4


@pytest.mark.now
def test_documents_post_error2(flask_client, user8, dev_app):
    """User should be given error if link already exists for that item."""
    access_token = api.create_token(user8, dev_app.client_id)
    response = flask_client.post(
        "/api/documents",
        headers={"authorization": "Bearer " + access_token},
        json={"title": "new item duplicate link", "link": "http://whatyouveread.com/1"},
    )
    json_data = response.get_json()
    docs = models.Documents.query.filter_by(user_id=user8.id).all()
    print(json_data)
    assert response.status_code == 400 and json_data["error"] == 63 and len(docs) == 4


####################
# INTEGRATION TEST #
####################


def test_integration(flask_client, dev_app, user4):
    """ Test from initial authorization to getting a document."""
    response = flask_client.post(
        "/api/authorize",
        data=dict(submit="Yes", client_id=dev_app.client_id, state="xyz"),
        follow_redirects=False,
    )

    # get code from the redirect url provided in api/authorize response
    # (can't do the redirect in Flask testing to exactly simulate what a client would do)
    redirect_url = response.headers["Location"]
    parsed_url = urlparse(redirect_url)
    query_params = parse_qs(parsed_url.query)
    authorization_code = query_params["code"][0]

    # now get the access token
    response = flask_client.post(
        "/api/token",
        data=dict(
            client_id=dev_app.client_id, grant_type="authorization_code", code=authorization_code
        ),
        follow_redirects=True,
    )

    # now use the token to get the user's documents
    access_token = response.get_json()["access_token"]
    response = flask_client.get(
        "/api/documents", headers={"authorization": "Bearer " + access_token}
    )
    json_data = response.get_json()

    assert len(json_data) == 4
