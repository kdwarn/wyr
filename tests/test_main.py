import pytest
import flask_login

# from app.models import User, Post
from app import main, models, db, common


def login(client, username, password, remember='', next=''):
    return client.post('/login', data=dict(
        wyr_username=username,
        wyr_password=password,
        remember=remember,
        next=next
    ), follow_redirects=True)


####################################
# USER AUTHENTICATION AND SETTINGS #
####################################

# logging in a user

def test_login_succeeds(client, user3):
    '''Login works properly.'''
    response = login(client, user3.username, 'testing3')

    assert b'Welcome back' in response.data


def test_login_no_username(client):
    '''No username found.'''
    response = login(client, 'kukenhof', 'some_password')
    assert b'Username does not exist' in response.data


def test_login_bad_password(client, user3):
    '''Incorrect password raises exception.'''

    response = login(client, user3.username, 'bad_password')
    assert b'Sorry, the password is incorrect' in response.data


# def test_next_redirect(client, user3):
#     '''Next redirect works correctly.'''

#     response = login(client, user3.username, 'testing3', next='/settings')
#     # print(response.status)
#     print(response.headers)
#     assert response.new_location == 'https://whatyouveread.com/settings'


# testing a logged-in user

def test_user_page1(client, user4):
    '''User profile page returns correctly.'''

    response = client.get('u/' + user4.username)
    assert b'Hello tester4' in response.data


def test_user_page2(client, user4):
    '''Trying to get another user's page fails.'''

    response = client.get('u/tester3', follow_redirects=True)
    assert b'Sorry, you cannot view that page.' in response.data


##############
# DOC ROUTES #
##############

# index

def test_index1(client, user4):
    '''index() displays all user's docs if they are logged in.'''
    response = client.get('/', follow_redirects=True)
    assert b'First user doc' in response.data


def test_index2(client, user1):
    '''index() displays login/signup page if user not logged in.'''
    response = client.get('/', follow_redirects=True)
    assert b'Welcome!' in response.data


# read

def test_read1(client, user4):
    '''read() displays all user's read docs if they are logged in.'''
    response = client.get('/read', follow_redirects=True)
    assert (b'First user doc' in response.data and
            b'Second user doc' not in response.data)


def test_read2(client, user1):
    '''read() displays login/signup page if user not logged in.'''
    response = client.get('/read', follow_redirects=True)
    assert b'Welcome!' in response.data


# to-read

def test_to_read1(client, user4):
    '''to_read() displays all user's read docs if they are logged in.'''
    response = client.get('/to-read', follow_redirects=True)
    assert (b'Second user doc' in response.data and
            b'First user doc' not in response.data)


def test_to_read2(client, user1):
    '''to_read() displays login/signup page if user not logged in.'''
    response = client.get('/to-read', follow_redirects=True)
    assert b'Welcome!' in response.data


# tags

def test_tags1(client, user4):
    '''tags() displays all user's tags if they are logged in.'''
    response = client.get('/tags', follow_redirects=True)
    assert (b'tag0' in response.data and
            b'JUMP TO' in response.data)


def test_tags2(client, user1):
    '''tags() displays login/signup page if user not logged in.'''
    response = client.get('/tags', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_tags3(client, user6):
    '''tags() returns user to main page if they have no tags.'''
    response = client.get('/tags', follow_redirects=True)
    assert b'You do not have any tags yet.' in response.data


def test_docs_by_tag1(client, user4):
    '''docs_by_tag() displays appropriate docs if user logged in.'''
    response = client.get('/all/tag/tag0', follow_redirects=True)
    assert (b'First user doc' in response.data and
            b'Third user doc' in response.data and
            b'Second user doc' not in response.data)


def test_docs_by_tag2(client, user4):
    '''docs_by_tag() displays appropriate docs if user logged in.'''
    response = client.get('/read/tag/tag0', follow_redirects=True)
    assert (b'First user doc' in response.data and
            b'Third user doc' not in response.data and
            b'Second user doc' not in response.data)


def test_docs_by_tag3(client, user4):
    '''docs_by_tag() displays appropriate docs if user logged in.'''
    response = client.get('/to-read/tag/tag0', follow_redirects=True)
    assert (b'First user doc' not in response.data and
            b'Third user doc' in response.data and
            b'Second user doc' not in response.data)


def test_docs_by_tag4(client, user0):
    '''docs_by_tag() displays login/signup page if user not logged in.'''
    response = client.get('/all/tag/tag0', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_tag5(client, user0):
    '''docs_by_tag() displays login/signup page if user not logged in.'''
    response = client.get('/read/tag/tag0', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_tag6(client, user0):
    '''docs_by_tag() displays login/signup page if user not logged in.'''
    response = client.get('/to-read/tag/tag0', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_tag7(client, user6):
    '''docs_by_tag() displays appropriate error message to user.'''
    response = client.get('/all/tag/tag0', follow_redirects=True)
    assert b'Sorry, you have no documents with that tag.' in response.data


def test_docs_by_tag8(client, user6):
    '''docs_by_tag() displays appropriate error message to user.'''
    response = client.get('/read/tag/tag0', follow_redirects=True)
    assert b'Sorry, you have no read documents with that tag.' in response.data


# authors

def test_docs_by_tag9(client, user6):
    '''docs_by_tag() displays appropriate error message to user.'''
    response = client.get('/to-read/tag/tag0', follow_redirects=True)
    assert b'Sorry, you have no to-read documents with that tag.' in response.data


def test_authors1(client, user4):
    '''authors() displays all user's authors if they are logged in.'''
    response = client.get('/authors', follow_redirects=True)
    assert (b'Smith, Joe' in response.data and
            b'JUMP TO' in response.data)


def test_authors2(client, user1):
    '''authors() displays login/signup page if user not logged in.'''
    response = client.get('/authors', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_authors3(client, user6):
    '''authors() returns user to main page if they have no authors.'''
    response = client.get('/authors', follow_redirects=True)
    assert b'You do not have any authors yet.' in response.data


def test_docs_by_author1(client, user4):
    '''docs_by_author() displays appropriate docs if user logged in.'''
    response = client.get('/all/author/2', follow_redirects=True)
    assert (b'First user doc' in response.data and
            b'Third user doc' in response.data and
            b'Second user doc' not in response.data and 
            b'Fourth user doc' not in response.data)


def test_docs_by_author2(client, user4):
    '''docs_by_author() displays appropriate docs if user logged in.'''
    response = client.get('/read/author/2', follow_redirects=True)
    assert (b'First user doc' in response.data and
            b'Third user doc' not in response.data and
            b'Second user doc' not in response.data and 
            b'Fourth user doc' not in response.data)


def test_docs_by_author3(client, user4):
    '''docs_by_author() displays appropriate docs if user logged in.'''
    response = client.get('/to-read/author/2', follow_redirects=True)
    assert (b'First user doc' not in response.data and
            b'Third user doc' in response.data and
            b'Second user doc' not in response.data and 
            b'Fourth user doc' not in response.data)


def test_docs_by_author4(client, user0):
    '''docs_by_author() displays login/signup page if user not logged in.'''
    response = client.get('/all/author/2', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_author5(client, user0):
    '''docs_by_author() displays login/signup page if user not logged in.'''
    response = client.get('/read/author/2', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_author6(client, user0):
    '''docs_by_author() displays login/signup page if user not logged in.'''
    response = client.get('/to-read/author/2', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_docs_by_author7(client, user6):
    '''docs_by_author() displays appropriate error message to user.'''
    response = client.get('/all/author/2', follow_redirects=True)
    assert b'Sorry, you have no documents by that author.' in response.data


def test_docs_by_author8(client, user6):
    '''docs_by_author() displays appropriate error message to user.'''
    response = client.get('/read/author/2', follow_redirects=True)
    assert b'Sorry, you have no read documents by that author.' in response.data


def test_docs_by_author9(client, user6):
    '''docs_by_author() displays appropriate error message to user.'''
    response = client.get('/to-read/author/2', follow_redirects=True)
    assert b'Sorry, you have no to-read documents by that author.' in response.data


# bunches - docs by read status and bunch name

def test_bunch(client, user0):
    '''bunch() displays login/signup page if user not logged in.'''
    response = client.get('/all/bunch/no bunch', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_bunch1(client, user4):
    '''bunch() shows message if no bunch with given name.'''
    response = client.get('all/bunch/no bunch', follow_redirects=True)
    assert b'No bunch named no bunch found' in response.data


def test_bunch2(client, user5):
    '''bunch() shows message if no read docs in bunch.'''
    response = client.get('read/bunch/bunch 3', follow_redirects=True)
    assert b'There are no read documents in the bunch bunch 3' in response.data


def test_bunch3(client, user5):
    '''bunch() shows message if no to-read docs in bunch.'''
    response = client.get('to-read/bunch/bunch 4', follow_redirects=True)
    assert b'There are no to-read documents in the bunch bunch 4' in response.data


def test_bunch4(client, user5):
    '''bunch() shows all docs in bunch (any read status).'''
    response = client.get('all/bunch/bunch 1')
    assert (b'First user doc' in response.data and 
            b'Second user doc' in response.data and 
            b'Third user doc' in response.data and
            b'Fourth user doc' in response.data)


def test_bunch5(client, user5):
    '''bunch() shows all read docs in bunch).'''
    response = client.get('read/bunch/bunch 1')
    assert (b'First user doc' in response.data and 
            b'Second user doc' not in response.data and 
            b'Third user doc' not in response.data and
            b'Fourth user doc' in response.data)


def test_bunch6(client, user5):
    '''bunch() shows all read docs in bunch).'''
    response = client.get('to-read/bunch/bunch 1')
    assert (b'First user doc' not in response.data and 
            b'Second user doc' in response.data and 
            b'Third user doc' in response.data and
            b'Fourth user doc' not in response.data)


# bunches - list of bunches/unsaved bunches

def test_bunches1(client, user0):
    '''bunches() displays login/signup page if user not logged in.'''
    response = client.get('/bunches', follow_redirects=True)
    assert b'Welcome!' in response.data


def test_bunches2(client, user6):
    '''bunches() displays no tags message if user has no tags.'''
    response = client.get('/bunches', follow_redirects=True)
    assert (b'Bunches are groups of tags' in response.data and 
            b'You do not yet have any tags to sort into bunches.' in response.data)


def test_bunches3(client, user4):
    '''bunches() displays no tags message if user has no tags.'''
    response = client.get('/bunches', follow_redirects=True)
    assert (b'Create New Bunch' in response.data and 
            b'You do not yet have any tags to sort into bunches.' not in response.data)


def test_bunches4(client, user5):
    '''bunches() displays list of user's bunches.'''
    response = client.get('/bunches')
    assert (b'bunch 1' in response.data and 
            b'bunch 2' in response.data and
            b'bunch 3' in response.data and
            b'bunch 4' in response.data)


def test_bunches5(client, user5):
    '''bunches() shows error messsage if user didn't select any tags.'''
    response = client.post('/bunches',  data=dict(
        selector='or',
        bunch_tags=[]
    ), follow_redirects=True)
    assert b'You did not choose any tags.' in response.data


def test_bunches6(client, user5):
    '''bunches() returns proper docs given chosen selector and tags.'''
    response = client.post('/bunches',  data=dict(
        selector='and',
        bunch_tags=[3, 5]
    ), follow_redirects=True)
    assert (b'First user doc' not in response.data and 
            b'Second user doc' in response.data and 
            b'Third user doc' not in response.data and
            b'Fourth user doc' not in response.data)


def test_bunches7(client, user5):
    '''bunches() returns proper docs given chosen selector and tags.'''
    response = client.post('/bunches',  data=dict(
        selector='or',
        bunch_tags=[2, 4]
    ), follow_redirects=True)
    assert (b'First user doc' in response.data and 
            b'Second user doc' in response.data and 
            b'Third user doc' not in response.data and
            b'Fourth user doc' not in response.data)


def test_bunches8(client, user5):
    '''bunches() shows error message if no docs matching criteria.'''
    response = client.post('/bunches',  data=dict(
        selector='and',
        bunch_tags=[2, 3]
    ), follow_redirects=True)
    assert (b'Sorry, no items matched your tag choices.' in response.data)


# bunches - save bunch

def test_bunch_save1(client, user5):

    response = client.post('/bunch/save', data=dict(
        selector='and',
        bunch_name='bunch5',
        bunch_tag_ids='3,5'
    ), follow_redirects=True)

    assert b'New bunch bunch5 saved' in response.data